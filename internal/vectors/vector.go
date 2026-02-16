package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

// VectorType represents the type of smuggling attack
type VectorType string

const (
	CLTE   VectorType = "CL.TE"
	TECL   VectorType = "TE.CL"
	H2TE   VectorType = "H2.TE"
	H2CL   VectorType = "H2.CL"
	TETE   VectorType = "TE.TE"
	CL0    VectorType = "CL.0"
	H2CRLF VectorType = "H2.CRLF"
)

// SmugglingVector defines the interface for all smuggling attack vectors
type SmugglingVector interface {
	// Name returns the descriptive name of the vector
	Name() string

	// Type returns the category of the vector
	Type() VectorType

	// GeneratePayloads creates a list of requests designed to test for this vector.
	// It takes a base request (usually a simple GET /) and transforms it.
	GeneratePayloads(baseReq *client.Request) []*client.Request

	// Verify checks if a response indicates susceptibility to this vector
	Verify(resp *client.Response) bool
}
