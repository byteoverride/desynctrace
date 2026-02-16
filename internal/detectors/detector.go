package detectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
)

type DetectionResult struct {
	IsVulnerable bool
	Vector       vectors.VectorType
	Confidence   int // 0-100
	Evidence     string
	Payload      *client.Request
}

type Detector interface {
	Detect(target string, vector vectors.SmugglingVector) (*DetectionResult, error)
}
