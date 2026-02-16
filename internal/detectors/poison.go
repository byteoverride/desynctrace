package detectors

import (
	"fmt"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
)

type PoisoningDetector struct {
	Client      client.Requester
	BaseHeaders map[string]string
}

func NewPoisoningDetector(c client.Requester, headers map[string]string) *PoisoningDetector {
	return &PoisoningDetector{Client: c, BaseHeaders: headers}
}

func (d *PoisoningDetector) Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error) {
	// 1. Benchmark normal response
	headers := map[string]string{
		"Host": "localhost",
	}
	for k, v := range d.BaseHeaders {
		headers[k] = v
	}

	baseReq := &client.Request{
		Method:  "GET",
		URL:     target,
		Headers: headers,
	}

	normalResp, err := d.Client.Do(baseReq, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	payloads := vector.GeneratePayloads(baseReq)

	for _, attackReq := range payloads {
		var requestClient client.Requester = d.Client
		if vector.Type() == vectors.H2CL || vector.Type() == vectors.H2TE {
			requestClient = client.NewRawH2Client(2 * time.Second)
		}

		// 2. Send Attack Request
		// We expect this one to succeed or timeout, but the key is the NEXT request.
		// We use a separate connection ideally, or the SAME connection?
		// CRITICAL: HTTP Desync attacks target the FRONTEND/BACKEND connection pool.
		// If we are the only user, we need to send the victim request on the same frontend connection
		// if the frontend reuses backend connections for the same client IP.
		// Often we need to send them back-to-back very quickly.

		// For true testing, we usually send them in a pipeline or immediately after on the SAME TCP connection
		// to the frontend if possible, or parallel connections if the backend pool is shared globally.
		// Sending on the same connection is the most reliable "self-poisoning" test.

		// Our client.Do implementation manages connections.
		// To force same connection, we might need a specific "Pipeline" or "Sequence" method in Client.
		// For now, let's assume the Client pool might reuse the connection if we are fast enough?
		// No, `fasthttp` or `net/http` pool behavior is complex.
		// Ideally we use the `RawClient` here to send both requests in one TCP stream.

		// But let's try sending sequentially with the high-level client first.

		requestClient.Do(attackReq, 2*time.Second)
		// We don't care much about the result of the attack request,
		// except that it shouldn't close the connection (Connection: close would make this fail).

		// 3. Send Victim Request
		victimReq := &client.Request{
			Method: "GET",
			URL:    target,
			Headers: map[string]string{
				"Host": "localhost",
			},
		}

		victimResp, err := d.Client.Do(victimReq, 5*time.Second)
		if err != nil {
			continue // Network error or timeout on victim request
		}

		// 4. Compare Victim Response to Baseline
		if victimResp.StatusCode != normalResp.StatusCode {
			return &DetectionResult{
				IsVulnerable: true,
				Vector:       vector.Type(),
				Confidence:   90,
				Evidence:     fmt.Sprintf("Victim response status changed: %d -> %d", normalResp.StatusCode, victimResp.StatusCode),
				Payload:      attackReq,
			}, nil
		}
	}

	return &DetectionResult{IsVulnerable: false}, nil
}
