package client

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

// Requester is the interface for HTTP clients
type Requester interface {
	Do(req *Request, timeout time.Duration) (*Response, error)
}

// Request represents a generic HTTP request
type Request struct {
	Method           string
	URL              string
	Headers          map[string]string
	Body             []byte
	Host             string
	TransferEncoding string
	ContentLength    int64
	RawHeaders       string // For advanced smuggling where we need exact byte control
}

// Response represents a generic HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Duration   time.Duration
}

// FastHTTPClient implements Requester using fasthttp
type FastHTTPClient struct {
	client *fasthttp.Client
}

func NewFastHTTPClient(insecure bool, proxyURL string) (*FastHTTPClient, error) {
	c := &fasthttp.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: insecure},
		// Adjust these for smuggling needs - we often need to keep connections open
		MaxConnsPerHost:     1000,
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxIdleConnDuration: 10 * time.Second,
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}

		if u.Scheme == "socks5" {
			// SOCKS5 using basic fasthttp proxy helper if available or custom logic
			// fasthttpproxy supports SOCKS5
			c.Dial = fasthttpproxy.FasthttpSocksDialer(u.Host)
		} else if u.Scheme == "http" || u.Scheme == "https" {
			// HTTP/HTTPS proxy
			c.Dial = fasthttpproxy.FasthttpHTTPDialer(u.Host)
		}
	}

	return &FastHTTPClient{client: c}, nil
}

func (c *FastHTTPClient) Do(req *Request, timeout time.Duration) (*Response, error) {
	fastReq := fasthttp.AcquireRequest()
	fastResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(fastReq)
	defer fasthttp.ReleaseResponse(fastResp)

	fastReq.SetRequestURI(req.URL)
	fastReq.Header.SetMethod(req.Method)

	if req.Host != "" {
		fastReq.SetHost(req.Host)
	}

	for k, v := range req.Headers {
		fastReq.Header.Set(k, v)
	}

	if req.TransferEncoding != "" {
		fastReq.Header.Set("Transfer-Encoding", req.TransferEncoding)
	}

	if req.ContentLength > 0 {
		fastReq.Header.SetContentLength(int(req.ContentLength))
	} else if len(req.Body) > 0 {
		fastReq.SetBody(req.Body)
		fastReq.Header.SetContentLength(len(req.Body))
	}

	// For raw headers, we might need a custom implementation that bypasses
	// fasthttp's normalization. For now, we use standard fasthttp helpers.
	// Actual smuggling might require writing raw bytes to the connection.

	start := time.Now()
	// Create a deadline context or modify client locally if needed, but fasthttp handles timeouts on client struct.
	// Since we share the client, we rely on ReadTimeout/WriteTimeout or per-request deadline if implemented manually.
	// fasthttp request has SetReadTimeout.

	// We can set timeout on the request itself if needed, but client timeout is global.
	// For now, assume client timeout covers us.

	err := c.client.Do(fastReq, fastResp)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	resp := &Response{
		StatusCode: fastResp.StatusCode(),
		Headers:    make(map[string]string),
		Body:       append([]byte(nil), fastResp.Body()...),
		Duration:   duration,
	}

	fastResp.Header.VisitAll(func(key, value []byte) {
		resp.Headers[string(key)] = string(value)
	})

	return resp, nil
}
