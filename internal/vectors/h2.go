package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

type H2Vector struct{}

func NewH2Vector() *H2Vector {
	return &H2Vector{}
}

func (v *H2Vector) Name() string {
	return "H2.CL/TE (HTTP/2 -> HTTP/1.1 Downgrade Smuggling)"
}

func (v *H2Vector) Type() VectorType {
	return H2CL // defaulting to H2.CL but handles both
}

func (v *H2Vector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// H2.CL Payload: Content-Length: 0 but send body
	// This poisons the socket for the NEXT request.

	// Payload:
	// HEADERS: ... Content-Length: 0 ...
	// DATA: SMUGGLED

	// When backend Downgrades:
	// POST / HTTP/1.1
	// ...
	// Content-Length: 0
	//
	// SMUGGLED

	// Backend reads header, sees 0, thinks request done.
	// "SMUGGLED" sets at start of next request.

	req1 := &client.Request{
		Method:  "POST",
		URL:     baseReq.URL,
		Headers: map[string]string{
			// "Content-Length": "0", // Handled by standard struct field below
		},
		ContentLength: 0,                  // Explicitly 0
		Body:          []byte("SMUGGLED"), // Data that shouldn't be there according to CL
	}

	// Note: The Detector needs to use RawH2Client for this request specifically.
	// We can mark this request or rely on the fact that an H2 vector implies H2 usage?
	// Currently Detectors simply call client.Do.
	// If standard client is used, it might strip the body if CL is 0.
	// We need to ensure the correct client is used.

	payloads = append(payloads, req1)
	return payloads
}

func (v *H2Vector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 500
}
