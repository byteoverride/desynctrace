package client

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"
)

// NetHTTPClient implements Requester using net/http
type NetHTTPClient struct {
	client *http.Client
}

func NewNetHTTPClient(insecure bool, proxyURL string) (*NetHTTPClient, error) {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		DisableKeepAlives: false, // We usually want keep-alives for smuggling
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		// http.Transport handles HTTP/SOCKS5 proxies via Proxy field
		tr.Proxy = http.ProxyURL(u)
	}

	return &NetHTTPClient{
		client: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
			// We don't want to follow redirects automatically during smuggling detection usually
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *NetHTTPClient) Do(req *Request, timeout time.Duration) (*Response, error) {
	// Create net/http request
	stdReq, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	for k, v := range req.Headers {
		stdReq.Header.Set(k, v)
	}

	// Note: net/http is very strict about Content-Length and Transfer-Encoding.
	// It will likely override or fail if we try to set conflicting ones.
	// This client is mostly for baseline checks, not the active smuggling exploitation.

	start := time.Now()
	stdResp, err := c.client.Do(stdReq)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer stdResp.Body.Close()

	body, err := io.ReadAll(stdResp.Body)
	if err != nil {
		return nil, err
	}

	resp := &Response{
		StatusCode: stdResp.StatusCode,
		Headers:    make(map[string]string),
		Body:       body,
		Duration:   duration,
	}

	for k, v := range stdResp.Header {
		if len(v) > 0 {
			resp.Headers[k] = v[0]
		}
	}

	return resp, nil
}
