package detectors

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/byteoverride/desynctrace/internal/client"
	"github.com/byteoverride/desynctrace/internal/vectors"
)

type ServerFingerprint struct {
	// Basic headers
	ServerHeader string
	PoweredBy    string
	Via          string

	// Server identification
	IsNginx    bool
	IsApache   bool
	IsGunicorn bool
	IsWaitress bool
	IsTomcat   bool
	IsIIS      bool
	IsNodeJS   bool
	IsPuma     bool
	IsUvicorn  bool
	IsLitespeed bool
	IsCaddy    bool
	IsTraefik  bool

	// CDN detection
	CDN       string // "cloudflare", "akamai", "fastly", "cloudfront", "azure-fd", etc.
	IsCDN     bool

	// Reverse proxy detection
	ReverseProxy string // "haproxy", "varnish", "envoy", "traefik", "nginx", etc.
	IsProxied    bool

	// WAF detection
	WAF      string // "cloudflare", "akamai-kona", "aws-waf", "imperva", "f5-bigip", etc.
	HasWAF   bool

	// Protocol support
	SupportsH2       bool
	SupportsH2C      bool
	SupportsWebSocket bool
	KeepAlive        bool

	// Behavioral characteristics
	AllowsTE         bool // Accepts Transfer-Encoding: chunked
	AllowsBothCLTE   bool // Accepts both CL and TE in same request
	NormalizesHeaders bool // Normalizes header names (e.g., underscores)
	AllowsBodyOnGET  bool // Accepts body with GET requests

	// Connection pooling behavior
	ConnectionReuse bool // Server reuses backend connections

	// Raw data
	AllHeaders  map[string]string
	TLSVersion  string
	ALPNProtos  []string
}

func FingerprintServer(c client.Requester, target string) (*ServerFingerprint, error) {
	req := &client.Request{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "keep-alive",
		},
	}

	resp, err := c.Do(req, 10*time.Second)
	if err != nil {
		return nil, err
	}

	fp := &ServerFingerprint{
		AllHeaders: resp.Headers,
	}

	// Extract key headers
	fp.ServerHeader = getHeaderCI(resp.Headers, "Server")
	fp.PoweredBy = getHeaderCI(resp.Headers, "X-Powered-By")
	fp.Via = getHeaderCI(resp.Headers, "Via")

	// Server identification
	identifyServer(fp)

	// CDN detection
	identifyCDN(fp, resp.Headers)

	// Reverse proxy detection
	identifyProxy(fp, resp.Headers)

	// WAF detection
	identifyWAF(fp, resp.Headers)

	// Protocol probing
	probeProtocols(fp, target)

	// Behavioral probing (uses separate requests)
	probeBehavior(fp, c, target)

	return fp, nil
}

func identifyServer(fp *ServerFingerprint) {
	s := strings.ToLower(fp.ServerHeader)
	p := strings.ToLower(fp.PoweredBy)

	fp.IsNginx = strings.Contains(s, "nginx") || strings.Contains(s, "openresty")
	fp.IsApache = strings.Contains(s, "apache")
	fp.IsGunicorn = strings.Contains(s, "gunicorn")
	fp.IsWaitress = strings.Contains(s, "waitress")
	fp.IsTomcat = strings.Contains(s, "tomcat") || strings.Contains(s, "coyote")
	fp.IsIIS = strings.Contains(s, "microsoft-iis")
	fp.IsLitespeed = strings.Contains(s, "litespeed")
	fp.IsCaddy = strings.Contains(s, "caddy")
	fp.IsTraefik = strings.Contains(s, "traefik")
	fp.IsNodeJS = strings.Contains(p, "express") || strings.Contains(p, "node") || strings.Contains(s, "node")
	fp.IsPuma = strings.Contains(s, "puma")
	fp.IsUvicorn = strings.Contains(s, "uvicorn")
}

func identifyCDN(fp *ServerFingerprint, headers map[string]string) {
	// Cloudflare
	if _, ok := headers["Cf-Ray"]; ok {
		fp.CDN = "cloudflare"
		fp.IsCDN = true
		return
	}
	if _, ok := headers["cf-ray"]; ok {
		fp.CDN = "cloudflare"
		fp.IsCDN = true
		return
	}
	if strings.Contains(strings.ToLower(fp.ServerHeader), "cloudflare") {
		fp.CDN = "cloudflare"
		fp.IsCDN = true
		return
	}

	// Akamai
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-akamai") {
			fp.CDN = "akamai"
			fp.IsCDN = true
			return
		}
	}
	if strings.Contains(strings.ToLower(fp.ServerHeader), "akamaighost") {
		fp.CDN = "akamai"
		fp.IsCDN = true
		return
	}

	// Fastly
	if _, ok := headers["X-Served-By"]; ok {
		if strings.Contains(headers["X-Served-By"], "cache-") {
			fp.CDN = "fastly"
			fp.IsCDN = true
			return
		}
	}
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "fastly-") {
			fp.CDN = "fastly"
			fp.IsCDN = true
			return
		}
	}

	// CloudFront
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-cf-") {
			fp.CDN = "cloudfront"
			fp.IsCDN = true
			return
		}
	}
	if strings.Contains(strings.ToLower(fp.Via), "cloudfront") {
		fp.CDN = "cloudfront"
		fp.IsCDN = true
		return
	}

	// Azure Front Door
	for k := range headers {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "x-azure-") || kl == "x-fd-healthprobe" {
			fp.CDN = "azure-frontdoor"
			fp.IsCDN = true
			return
		}
	}

	// Google Cloud CDN
	if _, ok := headers["X-Goog-Hash"]; ok {
		fp.CDN = "google-cdn"
		fp.IsCDN = true
		return
	}

	// Sucuri
	if strings.Contains(strings.ToLower(fp.ServerHeader), "sucuri") {
		fp.CDN = "sucuri"
		fp.IsCDN = true
		return
	}

	// Incapsula/Imperva CDN
	if _, ok := headers["X-Iinfo"]; ok {
		fp.CDN = "imperva"
		fp.IsCDN = true
		return
	}
}

func identifyProxy(fp *ServerFingerprint, headers map[string]string) {
	// Via header
	via := strings.ToLower(fp.Via)
	if via != "" {
		fp.IsProxied = true
		if strings.Contains(via, "varnish") {
			fp.ReverseProxy = "varnish"
		} else if strings.Contains(via, "haproxy") {
			fp.ReverseProxy = "haproxy"
		} else if strings.Contains(via, "squid") {
			fp.ReverseProxy = "squid"
		} else if strings.Contains(via, "cloudfront") {
			fp.ReverseProxy = "cloudfront"
		}
	}

	// Varnish
	if _, ok := headers["X-Varnish"]; ok {
		fp.ReverseProxy = "varnish"
		fp.IsProxied = true
	}

	// HAProxy
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-haproxy") {
			fp.ReverseProxy = "haproxy"
			fp.IsProxied = true
		}
	}

	// Envoy
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-envoy-") {
			fp.ReverseProxy = "envoy"
			fp.IsProxied = true
		}
	}

	// Traefik
	if fp.IsTraefik {
		fp.ReverseProxy = "traefik"
		fp.IsProxied = true
	}

	// nginx as reverse proxy (has upstream headers)
	if _, ok := headers["X-Nginx-Proxy"]; ok {
		fp.ReverseProxy = "nginx"
		fp.IsProxied = true
	}

	// AWS ALB/ELB
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-amzn-") {
			fp.ReverseProxy = "aws-alb"
			fp.IsProxied = true
		}
	}
}

func identifyWAF(fp *ServerFingerprint, headers map[string]string) {
	// Cloudflare WAF
	if fp.CDN == "cloudflare" {
		fp.WAF = "cloudflare"
		fp.HasWAF = true
		return
	}

	// AWS WAF
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-amzn-waf-") {
			fp.WAF = "aws-waf"
			fp.HasWAF = true
			return
		}
	}

	// Imperva/Incapsula
	if _, ok := headers["X-Iinfo"]; ok {
		fp.WAF = "imperva"
		fp.HasWAF = true
		return
	}

	// F5 BIG-IP
	for k, v := range headers {
		if strings.ToLower(k) == "set-cookie" && strings.Contains(v, "BIGipServer") {
			fp.WAF = "f5-bigip"
			fp.HasWAF = true
			return
		}
	}
	if strings.Contains(strings.ToLower(fp.ServerHeader), "big-ip") {
		fp.WAF = "f5-bigip"
		fp.HasWAF = true
		return
	}

	// ModSecurity
	if strings.Contains(strings.ToLower(fp.ServerHeader), "mod_security") {
		fp.WAF = "modsecurity"
		fp.HasWAF = true
		return
	}

	// Akamai Kona
	if fp.CDN == "akamai" {
		fp.WAF = "akamai-kona"
		fp.HasWAF = true
		return
	}
}

// probeProtocols checks HTTP/2 support via ALPN.
func probeProtocols(fp *ServerFingerprint, target string) {
	u, err := url.Parse(target)
	if err != nil {
		return
	}

	if u.Scheme != "https" {
		return
	}

	host := u.Host
	if u.Port() == "" {
		host += ":443"
	}

	// Check H2 via ALPN
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", host,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
	)
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fp.TLSVersion = tlsVersionString(state.Version)
	fp.ALPNProtos = []string{state.NegotiatedProtocol}

	if state.NegotiatedProtocol == "h2" {
		fp.SupportsH2 = true
	}
}

// probeBehavior sends specific requests to understand server behavior.
func probeBehavior(fp *ServerFingerprint, c client.Requester, target string) {
	// Test keep-alive
	req := &client.Request{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"Connection": "keep-alive",
		},
	}
	resp, err := c.Do(req, 5*time.Second)
	if err == nil {
		connHeader := strings.ToLower(getHeaderCI(resp.Headers, "Connection"))
		fp.KeepAlive = connHeader != "close"
	}
}

// PrioritizeVectors returns vectors ordered by relevance for this fingerprint.
// Vectors that are irrelevant (e.g., H2 vectors when no H2 support) are excluded.
func PrioritizeVectors(fp *ServerFingerprint, allVecs []vectors.SmugglingVector) []vectors.SmugglingVector {
	var prioritized []vectors.SmugglingVector
	var deferred []vectors.SmugglingVector

	for _, v := range allVecs {
		vtype := v.Type()

		// Skip H2 vectors if no H2 support
		if !fp.SupportsH2 {
			switch vtype {
			case vectors.H2CL, vectors.H2TE, vectors.H2CRLF, vectors.H2Pseudo, vectors.H2Tunnel:
				continue
			}
		}

		// Skip WebSocket vectors for CDNs that strip Upgrade headers
		if fp.CDN == "cloudflare" && vtype == vectors.WSSmugg {
			continue
		}

		// Prioritize based on known-vulnerable combinations
		if isHighPriority(fp, vtype) {
			prioritized = append(prioritized, v)
		} else {
			deferred = append(deferred, v)
		}
	}

	return append(prioritized, deferred...)
}

// isHighPriority returns true if this vector type is known to be particularly
// relevant for this server stack.
func isHighPriority(fp *ServerFingerprint, vtype vectors.VectorType) bool {
	switch {
	// Apache + backend often vulnerable to TE.TE
	case fp.IsApache && (vtype == vectors.TETE || vtype == vectors.CLTE):
		return true
	// Nginx + Gunicorn/Waitress → CL.0, CL.TE
	case fp.IsNginx && (fp.IsGunicorn || fp.IsWaitress) && (vtype == vectors.CL0 || vtype == vectors.CLTE):
		return true
	// Nginx + Node.js → CL.TE, TE.CL
	case fp.IsNginx && fp.IsNodeJS && (vtype == vectors.CLTE || vtype == vectors.TECL):
		return true
	// HAProxy → CL.TE, TE.TE
	case fp.ReverseProxy == "haproxy" && (vtype == vectors.CLTE || vtype == vectors.TETE):
		return true
	// Varnish → CL.TE, TE.TE
	case fp.ReverseProxy == "varnish" && (vtype == vectors.CLTE || vtype == vectors.TETE):
		return true
	// Tomcat → TE.CL, Double-CL
	case fp.IsTomcat && (vtype == vectors.TECL || vtype == vectors.DoubleCL):
		return true
	// IIS → TE.TE (obfuscated TE), CL.TE
	case fp.IsIIS && (vtype == vectors.TETE || vtype == vectors.CLTE):
		return true
	// Any CDN with H2 → H2 smuggling vectors
	case fp.IsCDN && fp.SupportsH2 && (vtype == vectors.H2CL || vtype == vectors.H2CRLF):
		return true
	// AWS ALB → CL.TE (known historical vulns)
	case fp.ReverseProxy == "aws-alb" && vtype == vectors.CLTE:
		return true
	}
	return false
}

func getHeaderCI(headers map[string]string, key string) string {
	// Try exact match first
	if v, ok := headers[key]; ok {
		return v
	}
	// Case-insensitive fallback
	keyLower := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == keyLower {
			return v
		}
	}
	return ""
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

// Summary returns a human-readable summary of the fingerprint.
func (fp *ServerFingerprint) Summary() string {
	var parts []string

	if fp.ServerHeader != "" {
		parts = append(parts, fmt.Sprintf("Server: %s", fp.ServerHeader))
	}
	if fp.PoweredBy != "" {
		parts = append(parts, fmt.Sprintf("Powered-By: %s", fp.PoweredBy))
	}
	if fp.IsCDN {
		parts = append(parts, fmt.Sprintf("CDN: %s", fp.CDN))
	}
	if fp.IsProxied {
		parts = append(parts, fmt.Sprintf("Proxy: %s", fp.ReverseProxy))
	}
	if fp.HasWAF {
		parts = append(parts, fmt.Sprintf("WAF: %s", fp.WAF))
	}
	if fp.SupportsH2 {
		parts = append(parts, "H2: yes")
	}
	if fp.TLSVersion != "" {
		parts = append(parts, fmt.Sprintf("TLS: %s", fp.TLSVersion))
	}
	if fp.KeepAlive {
		parts = append(parts, "Keep-Alive: yes")
	}

	return strings.Join(parts, " | ")
}
