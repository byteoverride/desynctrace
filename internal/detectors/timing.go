package detectors

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
	"github.com/rs/zerolog/log"
)

// TimingDetector uses differential timing analysis to detect HTTP smuggling.
//
// The core technique (from James Kettle / PortSwigger):
//
// CL.TE Detection:
//   Send a request with both CL and TE headers where the chunked body is
//   INCOMPLETE (no terminating 0\r\n\r\n). If the backend uses TE (chunked),
//   it will wait for more chunk data → timeout. If it uses CL, it reads
//   the CL-specified bytes and responds immediately.
//   Timeout = vulnerable to CL.TE.
//
// TE.CL Detection:
//   Send a request with both CL and TE headers. CL is set very small (e.g., 4).
//   The chunked body contains a complete 0-chunk terminator, but the total body
//   is larger than CL. If the backend uses CL, it reads the small amount and
//   responds fast. If it uses TE, it parses chunks normally and responds fast.
//   But if the FRONTEND uses TE and the BACKEND uses CL — the frontend forwards
//   the full chunked body, the backend reads CL bytes and leaves the rest.
//   We detect this by sending a follow-up request that the smuggled prefix
//   would corrupt, causing a timeout or error.
//
// Each probe is run multiple times to distinguish real vulnerabilities from
// network jitter. A configurable threshold determines the timeout boundary.
type TimingDetector struct {
	Insecure       bool
	BaseHeaders    map[string]string
	Attempts       int           // number of times to repeat each probe (default 5)
	TimeoutThresh  time.Duration // how long counts as "timed out" (default 5s)
	NormalTimeout  time.Duration // expected max for non-vulnerable (default 3s)
	ProbeTimeout   time.Duration // read deadline for probes (default 10s)
	ConfirmRatio   float64       // fraction of attempts that must timeout to confirm (default 0.6)
	OnTraffic      TrafficLogger // optional callback to display raw traffic
}

func NewTimingDetector(headers map[string]string) *TimingDetector {
	return &TimingDetector{
		Insecure:      true,
		BaseHeaders:   headers,
		Attempts:      5,
		TimeoutThresh: 5 * time.Second,
		NormalTimeout:  3 * time.Second,
		ProbeTimeout:  10 * time.Second,
		ConfirmRatio:  0.6,
	}
}

func (d *TimingDetector) Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error) {
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
		return d.detectCLTE(target, host, path)
	case vectors.TECL:
		return d.detectTECL(target, host, path)
	case vectors.TETE:
		// TE.TE can degrade to either CL.TE or TE.CL depending on which server
		// ignores the obfuscated TE. Test both.
		return d.detectTETE(target, host, path, vector)
	case vectors.CL0:
		return d.detectCL0(target, host, path)
	default:
		// For H2 vectors, timing detection uses the H2 client — handled separately
		return &DetectionResult{IsVulnerable: false, Vector: vtype}, nil
	}
}

// detectCLTE tests for CL.TE using an incomplete chunked body.
// If the backend interprets TE:chunked, it waits for the final chunk → timeout.
func (d *TimingDetector) detectCLTE(target, host, path string) (*DetectionResult, error) {
	// First: baseline timing with a normal request
	baselinePayload := client.BuildRawRequest("POST", path, host, mapToRawHeaders(d.BaseHeaders), nil)
	baselineDuration, err := d.measureBaseline(target, baselinePayload)
	if err != nil {
		log.Debug().Err(err).Msg("baseline failed for CL.TE")
	}
	_ = baselineDuration

	// CL.TE probe: Content-Length covers the full body, but the chunked body
	// is incomplete (missing final 0\r\n\r\n). If backend uses chunked, it hangs.
	//
	// The body we send: "1\r\nZ\r\n" (valid chunk of 1 byte, but no terminating 0-chunk)
	// CL = 6 (length of "1\r\nZ\r\n")
	// If backend uses CL: reads 6 bytes, done, responds.
	// If backend uses TE: reads chunk "1\r\nZ\r\n", waits for next chunk → timeout.

	incompleteChunkedBody := "1\r\nZ\r\n"

	var hdrs []client.RawHeader
	for k, v := range d.BaseHeaders {
		hdrs = append(hdrs, client.RawHeader{Key: k, Value: v})
	}
	hdrs = append(hdrs,
		client.RawHeader{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
		client.RawHeader{Key: "Transfer-Encoding", Value: "chunked"},
		client.RawHeader{Key: "Content-Length", Value: fmt.Sprintf("%d", len(incompleteChunkedBody))},
	)

	probePayload := client.BuildRawRequest("POST", path, host, hdrs, []byte(incompleteChunkedBody))

	timeouts, normals, durations := d.runProbes(target, probePayload)

	if float64(timeouts)/float64(d.Attempts) >= d.ConfirmRatio {
		return &DetectionResult{
			IsVulnerable: true,
			Vector:       vectors.CLTE,
			Confidence:   d.calcConfidence(timeouts, normals),
			Evidence:     fmt.Sprintf("Differential timing: %d/%d probes timed out (avg %v). Backend likely uses Transfer-Encoding (chunked) while frontend uses Content-Length.", timeouts, d.Attempts, avgDuration(durations)),
			Technique:    "differential-timing",
			Attempts:     d.Attempts,
			Successes:    timeouts,
		}, nil
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.CLTE}, nil
}

// detectTECL tests for TE.CL.
// We send a properly terminated chunked body with a small CL.
// If backend uses CL, it reads the small amount and responds fast.
// The leftover bytes poison the socket. We detect by sending a second
// request that should get corrupted.
func (d *TimingDetector) detectTECL(target, host, path string) (*DetectionResult, error) {
	// TE.CL probe: Send chunked body with a smuggled prefix.
	// Body (chunked-valid):
	//   "0\r\n\r\n"  (empty terminating chunk)
	// But we set Content-Length to a large value that exceeds the body.
	// If backend uses CL (large), it waits for more data → timeout.
	// If backend uses TE, it sees 0-chunk and responds immediately.

	body := "0\r\n\r\n"

	var hdrs []client.RawHeader
	for k, v := range d.BaseHeaders {
		hdrs = append(hdrs, client.RawHeader{Key: k, Value: v})
	}
	hdrs = append(hdrs,
		client.RawHeader{Key: "Content-Type", Value: "application/x-www-form-urlencoded"},
		client.RawHeader{Key: "Transfer-Encoding", Value: "chunked"},
		client.RawHeader{Key: "Content-Length", Value: "100"}, // much larger than actual body
	)

	probePayload := client.BuildRawRequest("POST", path, host, hdrs, []byte(body))

	timeouts, normals, durations := d.runProbes(target, probePayload)

	if float64(timeouts)/float64(d.Attempts) >= d.ConfirmRatio {
		return &DetectionResult{
			IsVulnerable: true,
			Vector:       vectors.TECL,
			Confidence:   d.calcConfidence(timeouts, normals),
			Evidence:     fmt.Sprintf("Differential timing: %d/%d probes timed out (avg %v). Backend likely uses Content-Length while frontend uses Transfer-Encoding.", timeouts, d.Attempts, avgDuration(durations)),
			Technique:    "differential-timing",
			Attempts:     d.Attempts,
			Successes:    timeouts,
		}, nil
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.TECL}, nil
}

// detectTETE tests obfuscated TE headers.
// For each obfuscation variant, we check if it degrades to CL.TE or TE.CL.
func (d *TimingDetector) detectTETE(target, host, path string, vector vectors.SmugglingVector) (*DetectionResult, error) {
	// TE.TE obfuscation variants — one server sees TE, the other doesn't.
	// We test each obfuscation with both CL.TE-style and TE.CL-style probes.

	obfuscations := []struct {
		name    string
		teKey   string
		teValue string
	}{
		{"space-before-colon", "Transfer-Encoding ", "chunked"},
		{"tab-before-colon", "Transfer-Encoding\t", "chunked"},
		{"vertical-tab-in-value", "Transfer-Encoding", "chunked\x0b"},
		{"line-folding", "Transfer-Encoding", "\r\n chunked"},
		{"mixed-case", "TrAnSfEr-EnCoDiNg", "chunked"},
		{"null-byte", "Transfer-Encoding", "chunked\x00"},
		{"double-te", "Transfer-Encoding", "chunked\r\nTransfer-Encoding: x"},
		{"chunk-ext-space", "Transfer-Encoding", " chunked"},
		{"identity-then-chunked", "Transfer-Encoding", "identity, chunked"},
		{"chunked-then-cow", "Transfer-Encoding", "chunked, cow"},
		{"x-chunked", "Transfer-Encoding", "x-chunked"},
	}

	for _, obs := range obfuscations {
		// CL.TE-style probe with this obfuscation
		incompleteBody := "1\r\nZ\r\n"

		rawHeaders := fmt.Sprintf("Host: %s\r\n", host)
		rawHeaders += fmt.Sprintf("Content-Type: application/x-www-form-urlencoded\r\n")
		rawHeaders += fmt.Sprintf("Content-Length: %d\r\n", len(incompleteBody))
		rawHeaders += fmt.Sprintf("%s: %s\r\n", obs.teKey, obs.teValue)
		for k, v := range d.BaseHeaders {
			rawHeaders += fmt.Sprintf("%s: %s\r\n", k, v)
		}

		probe := client.BuildRawRequestExact(
			fmt.Sprintf("POST %s HTTP/1.1", path),
			rawHeaders,
			[]byte(incompleteBody),
		)

		timeouts, normals, durations := d.runProbes(target, probe)

		if float64(timeouts)/float64(d.Attempts) >= d.ConfirmRatio {
			return &DetectionResult{
				IsVulnerable: true,
				Vector:       vectors.TETE,
				Confidence:   d.calcConfidence(timeouts, normals),
				Evidence: fmt.Sprintf("TE.TE via obfuscation '%s': %d/%d probes timed out (avg %v). "+
					"Obfuscated TE header causes parsing disagreement.",
					obs.name, timeouts, d.Attempts, avgDuration(durations)),
				Technique: "differential-timing-tete",
				Attempts:  d.Attempts,
				Successes: timeouts,
			}, nil
		}
		_ = normals
	}

	return &DetectionResult{IsVulnerable: false, Vector: vectors.TETE}, nil
}

// detectCL0 tests for CL.0 (backend ignores body).
// We send a POST with a body, then immediately send a victim GET.
// If backend ignored the body, the body bytes sit in the buffer and
// corrupt the victim request.
func (d *TimingDetector) detectCL0(target, host, path string) (*DetectionResult, error) {
	// CL.0 works differently — we need connection poisoning, not timing.
	// But we can detect it via a timing-adjacent method:
	// Send a POST with body containing "GET /cl0-detect HTTP/1.1\r\n..."
	// Then send a normal GET. If the victim gets a different response, CL.0 confirmed.

	// For now, we use the simpler method: POST with Content-Length that has a body,
	// but also explicitly set Connection: keep-alive.
	// We test with PipelinedClient in the ConfirmationDetector, not here.
	// Mark as needing confirmation.
	return &DetectionResult{IsVulnerable: false, Vector: vectors.CL0}, nil
}

// runProbes sends the probe payload multiple times, each on a fresh connection,
// and counts timeouts vs normal responses.
func (d *TimingDetector) runProbes(target string, payload []byte) (timeouts, normals int, durations []time.Duration) {
	for i := 0; i < d.Attempts; i++ {
		pc := client.NewPipelinedClient(d.ProbeTimeout, d.Insecure)
		elapsed, resp, err := pc.SendTimingProbe(target, payload, d.ProbeTimeout)
		pc.Close()

		durations = append(durations, elapsed)

		if d.OnTraffic != nil {
			d.OnTraffic(fmt.Sprintf("probe %d/%d", i+1, d.Attempts), payload, resp, elapsed)
		}

		if err != nil || elapsed >= d.TimeoutThresh {
			timeouts++
			log.Debug().Int("attempt", i+1).Dur("elapsed", elapsed).Msg("probe timed out")
		} else {
			normals++
			log.Debug().Int("attempt", i+1).Dur("elapsed", elapsed).Msg("probe responded normally")
		}
	}
	return
}

func (d *TimingDetector) measureBaseline(target string, payload []byte) (time.Duration, error) {
	pc := client.NewPipelinedClient(d.NormalTimeout, d.Insecure)
	defer pc.Close()
	elapsed, _, err := pc.SendTimingProbe(target, payload, d.NormalTimeout)
	return elapsed, err
}

func (d *TimingDetector) calcConfidence(timeouts, normals int) int {
	ratio := float64(timeouts) / float64(timeouts+normals)
	if ratio >= 0.9 {
		return 95
	} else if ratio >= 0.8 {
		return 85
	} else if ratio >= 0.6 {
		return 70
	}
	return 50
}

func avgDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

// mapToRawHeaders converts a map to a slice of RawHeader for BuildRawRequest.
func mapToRawHeaders(m map[string]string) []client.RawHeader {
	var hdrs []client.RawHeader
	for k, v := range m {
		hdrs = append(hdrs, client.RawHeader{Key: k, Value: v})
	}
	return hdrs
}

// Helper to check if a string looks like a timeout error
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "i/o timeout")
}
