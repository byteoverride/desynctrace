package detectors

import (
	"fmt"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
)

type BlindDetector struct {
	Client      client.Requester
	BaseHeaders map[string]string
}

func NewBlindDetector(c client.Requester, headers map[string]string) *BlindDetector {
	return &BlindDetector{Client: c, BaseHeaders: headers}
}

func (d *BlindDetector) Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error) {
	// Base request
	headers := map[string]string{
		"Host": "localhost", // Should parse from target
	}
	for k, v := range d.BaseHeaders {
		headers[k] = v
	}

	baseReq := &client.Request{
		Method:  "GET",
		URL:     target,
		Headers: headers,
	}

	payloads := vector.GeneratePayloads(baseReq)

	for _, payload := range payloads {
		// Use specialized client if needed
		var requestClient client.Requester = d.Client

		// If vector is H2, try to cast to RawH2Client or create one
		// Ideally we detect this via vector type or capability.
		if vector.Type() == vectors.H2CL || vector.Type() == vectors.H2TE {
			// Create raw H2 client
			// This is a bit ad-hoc, ideally the factory handles this.
			requestClient = client.NewRawH2Client(5 * time.Second)
		}

		start := time.Now()
		resp, err := requestClient.Do(payload, 5*time.Second)
		duration := time.Since(start)

		if err != nil {
			// Timeout is often a good sign for smuggling (backend waiting for remaining bytes)
			if duration >= 4*time.Second { // Threshold
				return &DetectionResult{
					IsVulnerable: true,
					Vector:       vector.Type(),
					Confidence:   80,
					Evidence:     fmt.Sprintf("Request timeout/delay detected: %v", duration),
					Payload:      payload,
				}, nil
			}
		} else {
			// Check response
			if vector.Verify(resp) {
				return &DetectionResult{
					IsVulnerable: true,
					Vector:       vector.Type(),
					Confidence:   60,
					Evidence:     fmt.Sprintf("Suspicious response code: %d", resp.StatusCode),
					Payload:      payload,
				}, nil
			}
		}
	}

	return &DetectionResult{IsVulnerable: false}, nil
}
