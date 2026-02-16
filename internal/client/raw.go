package client

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"
)

// RawClient allows sending raw bytes to a target, bypassing HTTP client normalization completely
type RawClient struct {
	Timeout  time.Duration
	Insecure bool
}

func NewRawClient(timeout time.Duration, insecure bool) *RawClient {
	return &RawClient{
		Timeout:  timeout,
		Insecure: insecure,
	}
}

func (c *RawClient) Do(targetURL string, rawRequest []byte) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	var conn net.Conn
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
		conf := &tls.Config{InsecureSkipVerify: c.Insecure}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, conf)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(rawRequest); err != nil {
		return nil, err
	}

	// Read response
	// This is a simplified reader, in a real scenario we'd want to parse HTTP properly
	// or read until EOF/timeout
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		// If we read something before error, return it
		if n > 0 {
			return response[:n], nil
		}
		return nil, err
	}

	return response[:n], nil
}
