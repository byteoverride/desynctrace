package detectors

import (
	"strings"

	"github.com/byteoverride/desynctrace/internal/client"
)

type ServerFingerprint struct {
	ServerHeader string
	PoweredBy    string
	Via          string
	IsNginx      bool
	IsApache     bool
	IsGunicorn   bool
}

func FingerprintServer(c client.Requester, target string) (*ServerFingerprint, error) {
	req := &client.Request{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"User-Agent": "DesyncTrace/1.0",
		},
	}

	resp, err := c.Do(req, 0)
	if err != nil {
		return nil, err
	}

	fp := &ServerFingerprint{
		ServerHeader: resp.Headers["Server"],
		PoweredBy:    resp.Headers["X-Powered-By"],
		Via:          resp.Headers["Via"],
	}

	serverLower := strings.ToLower(fp.ServerHeader)
	fp.IsNginx = strings.Contains(serverLower, "nginx")
	fp.IsApache = strings.Contains(serverLower, "apache")
	fp.IsGunicorn = strings.Contains(serverLower, "gunicorn")

	return fp, nil
}
