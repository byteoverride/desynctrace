package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PipelinedClient sends attack + victim requests on the SAME TCP connection.
// This is critical for HTTP smuggling — the desync only manifests when the
// poisoned bytes sit in the backend's receive buffer for the next request
// on that same socket.
type PipelinedClient struct {
	Timeout       time.Duration
	Insecure      bool
	ReadBufSize   int
	conn          net.Conn
	reader        *bufio.Reader
	connected     bool
	currentTarget string
}

func NewPipelinedClient(timeout time.Duration, insecure bool) *PipelinedClient {
	return &PipelinedClient{
		Timeout:     timeout,
		Insecure:    insecure,
		ReadBufSize: 65536,
	}
}

// Connect establishes a persistent TCP/TLS connection to the target.
func (c *PipelinedClient) Connect(targetURL string) error {
	if c.connected && c.currentTarget == targetURL {
		return nil // reuse
	}
	c.Close()

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	address := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			address += ":443"
		} else {
			address += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: c.Timeout}

	if u.Scheme == "https" {
		hostname := u.Hostname()
		conf := &tls.Config{
			InsecureSkipVerify: c.Insecure,
			ServerName:         hostname,
			NextProtos:         []string{"http/1.1"},
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
		if err != nil {
			return fmt.Errorf("TLS dial failed: %w", err)
		}
		c.conn = conn
	} else {
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			return fmt.Errorf("TCP dial failed: %w", err)
		}
		c.conn = conn
	}

	c.reader = bufio.NewReaderSize(c.conn, c.ReadBufSize)
	c.connected = true
	c.currentTarget = targetURL
	return nil
}

// Close tears down the connection.
func (c *PipelinedClient) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
	c.currentTarget = ""
	c.reader = nil
}

// SendRaw writes arbitrary bytes to the connection without any normalization.
func (c *PipelinedClient) SendRaw(data []byte) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}
	c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	_, err := c.conn.Write(data)
	return err
}

// ReadRawResponse reads a single HTTP/1.x response from the connection.
// It properly handles Content-Length, chunked transfer encoding, and
// connection close semantics.
func (c *PipelinedClient) ReadRawResponse(timeout time.Duration) (*RawHTTPResponse, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}
	c.conn.SetReadDeadline(time.Now().Add(timeout))

	resp := &RawHTTPResponse{
		Headers: make(map[string][]string),
	}

	// Read status line
	statusLine, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading status line: %w", err)
	}
	resp.RawStatusLine = strings.TrimRight(statusLine, "\r\n")

	parts := strings.SplitN(resp.RawStatusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed status line: %q", resp.RawStatusLine)
	}
	resp.Proto = parts[0]
	resp.StatusCode, _ = strconv.Atoi(parts[1])
	if len(parts) >= 3 {
		resp.StatusText = parts[2]
	}

	// Read headers
	var rawHeaders strings.Builder
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading headers: %w", err)
		}
		rawHeaders.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break // end of headers
		}
		colonIdx := strings.IndexByte(trimmed, ':')
		if colonIdx < 0 {
			continue // malformed header, skip
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := strings.TrimSpace(trimmed[colonIdx+1:])
		keyLower := strings.ToLower(key)
		resp.Headers[keyLower] = append(resp.Headers[keyLower], val)
	}
	resp.RawHeaders = rawHeaders.String()

	// Determine body reading strategy
	if isChunked(resp.Headers) {
		resp.Body, err = c.readChunkedBody()
		if err != nil {
			return nil, fmt.Errorf("reading chunked body: %w", err)
		}
	} else if cl := getContentLength(resp.Headers); cl >= 0 {
		resp.Body = make([]byte, cl)
		_, err = io.ReadFull(c.reader, resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading body (CL=%d): %w", cl, err)
		}
	} else if resp.StatusCode != 204 && resp.StatusCode != 304 {
		// No CL, no chunked — check for Connection: close
		if isConnectionClose(resp.Headers) {
			resp.Body, err = io.ReadAll(c.reader)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("reading body until close: %w", err)
			}
		}
		// else: no body (e.g., 1xx, or server expects keep-alive with no body indication)
	}

	return resp, nil
}

// SendAttackAndVictim sends an attack payload then a victim request on the
// same TCP connection, reads both responses. This is the core smuggling
// confirmation technique.
func (c *PipelinedClient) SendAttackAndVictim(
	targetURL string,
	attackPayload []byte,
	victimPayload []byte,
	delayBetween time.Duration,
	readTimeout time.Duration,
) (*RawHTTPResponse, *RawHTTPResponse, error) {
	if err := c.Connect(targetURL); err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}

	// Send attack
	if err := c.SendRaw(attackPayload); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("sending attack: %w", err)
	}

	// Read attack response
	attackResp, err := c.ReadRawResponse(readTimeout)
	if err != nil {
		// Timeout on attack response can itself be a signal
		attackResp = &RawHTTPResponse{StatusCode: 0, Error: err.Error()}
	}

	// Optional delay between attack and victim
	if delayBetween > 0 {
		time.Sleep(delayBetween)
	}

	// Send victim
	if err := c.SendRaw(victimPayload); err != nil {
		c.Close()
		return attackResp, nil, fmt.Errorf("sending victim: %w", err)
	}

	// Read victim response
	victimResp, err := c.ReadRawResponse(readTimeout)
	if err != nil {
		victimResp = &RawHTTPResponse{StatusCode: 0, Error: err.Error()}
	}

	return attackResp, victimResp, nil
}

// SendTimingProbe sends a single raw request and measures how long the
// server takes to respond. Used for differential timing detection.
func (c *PipelinedClient) SendTimingProbe(
	targetURL string,
	payload []byte,
	readTimeout time.Duration,
) (time.Duration, *RawHTTPResponse, error) {
	if err := c.Connect(targetURL); err != nil {
		return 0, nil, err
	}

	start := time.Now()
	if err := c.SendRaw(payload); err != nil {
		c.Close()
		return 0, nil, err
	}

	resp, err := c.ReadRawResponse(readTimeout)
	elapsed := time.Since(start)

	if err != nil {
		return elapsed, nil, err
	}
	return elapsed, resp, nil
}

// RawHTTPResponse holds a parsed HTTP response with access to raw data.
type RawHTTPResponse struct {
	Proto         string
	StatusCode    int
	StatusText    string
	RawStatusLine string
	RawHeaders    string
	Headers       map[string][]string
	Body          []byte
	Error         string
}

// GetHeader returns the first value for a header key (case-insensitive).
func (r *RawHTTPResponse) GetHeader(key string) string {
	vals := r.Headers[strings.ToLower(key)]
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// BuildRawRequest constructs a raw HTTP/1.1 request from components.
// This gives full control over header ordering, duplicate headers,
// malformed values, etc.
func BuildRawRequest(method, path, host string, headers []RawHeader, body []byte) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	b.WriteString(fmt.Sprintf("Host: %s\r\n", host))
	for _, h := range headers {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", h.Key, h.Value))
	}
	b.WriteString("\r\n")
	result := []byte(b.String())
	if len(body) > 0 {
		result = append(result, body...)
	}
	return result
}

// BuildRawRequestExact constructs a request with EXACT byte control.
// Headers are written exactly as provided — no normalization, no sorting.
// Use this for TE.TE obfuscation, header injection, etc.
func BuildRawRequestExact(requestLine string, rawHeaders string, body []byte) []byte {
	var b []byte
	b = append(b, []byte(requestLine+"\r\n")...)
	b = append(b, []byte(rawHeaders)...)
	b = append(b, []byte("\r\n")...)
	if len(body) > 0 {
		b = append(b, body...)
	}
	return b
}

// RawHeader is a key-value pair that preserves exact formatting.
type RawHeader struct {
	Key   string
	Value string
}

// readChunkedBody reads a chunked transfer-encoded body.
func (c *PipelinedClient) readChunkedBody() ([]byte, error) {
	var body []byte
	for {
		// Read chunk size line
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return body, err
		}
		line = strings.TrimRight(line, "\r\n")

		// Strip chunk extensions
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		size, err := strconv.ParseInt(line, 16, 64)
		if err != nil {
			return body, fmt.Errorf("invalid chunk size %q: %w", line, err)
		}

		if size == 0 {
			// Read trailing CRLF (and any trailers)
			for {
				trailer, err := c.reader.ReadString('\n')
				if err != nil {
					return body, nil // best effort
				}
				if strings.TrimRight(trailer, "\r\n") == "" {
					break
				}
			}
			return body, nil
		}

		chunk := make([]byte, size)
		_, err = io.ReadFull(c.reader, chunk)
		if err != nil {
			return body, err
		}
		body = append(body, chunk...)

		// Read trailing CRLF after chunk data
		c.reader.ReadString('\n')
	}
}

func isChunked(headers map[string][]string) bool {
	for _, v := range headers["transfer-encoding"] {
		if strings.Contains(strings.ToLower(v), "chunked") {
			return true
		}
	}
	return false
}

func getContentLength(headers map[string][]string) int64 {
	vals := headers["content-length"]
	if len(vals) == 0 {
		return -1
	}
	cl, err := strconv.ParseInt(strings.TrimSpace(vals[0]), 10, 64)
	if err != nil {
		return -1
	}
	return cl
}

func isConnectionClose(headers map[string][]string) bool {
	for _, v := range headers["connection"] {
		if strings.ToLower(v) == "close" {
			return true
		}
	}
	return false
}
