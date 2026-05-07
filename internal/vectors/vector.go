package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

// VectorType represents the type of smuggling attack
type VectorType string

const (
	CLTE      VectorType = "CL.TE"
	TECL      VectorType = "TE.CL"
	H2TE      VectorType = "H2.TE"
	H2CL      VectorType = "H2.CL"
	TETE      VectorType = "TE.TE"
	CL0       VectorType = "CL.0"
	H2CRLF    VectorType = "H2.CRLF"
	DoubleCL  VectorType = "Double-CL"
	ChunkExt  VectorType = "Chunk-Ext"
	H2Pseudo  VectorType = "H2.Pseudo"
	H2Tunnel  VectorType = "H2.Tunnel"
	WSSmugg   VectorType = "WS.Smuggle"
	HTTP09    VectorType = "HTTP/0.9"
	CLSpacing VectorType = "CL.Spacing"
)

// SmugglingVector defines the interface for all smuggling attack vectors
type SmugglingVector interface {
	// Name returns the descriptive name of the vector
	Name() string

	// Type returns the category of the vector
	Type() VectorType

	// GeneratePayloads creates a list of requests designed to test for this vector.
	GeneratePayloads(baseReq *client.Request) []*client.Request

	// GenerateRawPayloads creates raw byte payloads for use with the PipelinedClient.
	// These bypass all HTTP client normalization — essential for smuggling.
	GenerateRawPayloads(host, path string) []RawPayload

	// Verify checks if a response indicates susceptibility to this vector
	Verify(resp *client.Response) bool
}

// RawPayload represents a complete raw HTTP request as bytes,
// plus metadata about what it's testing.
type RawPayload struct {
	Name        string // descriptive name of this specific payload variant
	Data        []byte // raw bytes to send
	Description string // what this payload tests
	Technique   string // e.g., "incomplete-chunk", "double-cl", "obfuscated-te"
}

// AllVectors returns all implemented smuggling vectors.
func AllVectors() []SmugglingVector {
	return []SmugglingVector{
		NewCLTEVector(),
		NewTECLVector(),
		NewTETEVector(),
		NewCL0Vector(),
		NewH2Vector(),
		NewH2CRLFVector(),
		NewDoubleCLVector(),
		NewChunkExtVector(),
		NewCLSpacingVector(),
		NewH2PseudoVector(),
		NewH2TunnelVector(),
		NewWSSmuggleVector(),
		NewHTTP09Vector(),
	}
}
