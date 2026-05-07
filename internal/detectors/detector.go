package detectors

import (
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
)

type DetectionResult struct {
	IsVulnerable bool               `json:"is_vulnerable"`
	Vector       vectors.VectorType `json:"vector"`
	Confidence   int                `json:"confidence"` // 0-100
	Evidence     string             `json:"evidence"`
	Payload      *client.Request    `json:"payload,omitempty"`

	// Extended fields
	Technique string `json:"technique"`           // e.g., "differential-timing", "connection-poisoning"
	Attempts  int    `json:"attempts,omitempty"`   // total attempts
	Successes int    `json:"successes,omitempty"`  // successful detections
	Confirmed bool   `json:"confirmed"`           // poisoning-confirmed vs timing-suspected
	RawPayload []byte `json:"raw_payload,omitempty"` // exact bytes sent
	RawResponse []byte `json:"raw_response,omitempty"` // raw response received
	FPRisk     string `json:"fp_risk,omitempty"`   // "low", "medium", "high" false positive risk
}

type Detector interface {
	Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error)
}

// TrafficLogger is a callback for printing raw request/response traffic.
// Set this on detectors to get live visibility into what is being sent.
type TrafficLogger func(label string, data []byte, resp *client.RawHTTPResponse, elapsed time.Duration)
