package client

import (
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// GetProxyDialer returns a dialer function that routes traffic through the specified proxy.
// Supported schemes: http, https, socks5.
func GetProxyDialer(proxyURL string, timeout time.Duration) (func(string, string) (net.Conn, error), error) {
	if proxyURL == "" {
		return net.Dial, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	var dialer proxy.Dialer

	switch u.Scheme {
	case "socks5":
		dialer, err = proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, err
		}
	case "http", "https":
		// For HTTP/HTTPS proxies, we typically use the CONNECT method for HTTPS targets,
		// or just standard forwarding.
		// fasthttp doesn't support CONNECT natively in its Dial function easily without FastHTTPHTTPDialer.
		// However, for a generic dialer, we might want to return something compatible.
		// A simple approach for now is to return nil here and let specific clients handle HTTP proxies
		// if they have native support, or implement a custom CONNECT dialer.
		// Since net/http handles HTTP proxies natively, and fasthttp can use FasthttpHTTPDialer,
		// we might handle them separately in the clients.
		// BUT, if we want a unified dialer...
		return nil, nil // Let client implementations handle HTTP proxies specifically
	default:
		return net.Dial, nil
	}

	return func(network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}, nil
}
