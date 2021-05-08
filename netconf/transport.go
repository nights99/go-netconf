// Go NETCONF Client
//
// Copyright (c) 2013-2018, Juniper Networks, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netconf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

const (
	// msgSeperator is used to separate sent messages via NETCONF
	msgSeperator     = "]]>]]>"
	msgSeperator_v11 = "\n##\n"
)

// DefaultCapabilities sets the default capabilities of the client library
var DefaultCapabilities = []string{
	"urn:ietf:params:netconf:base:1.0",
	"urn:ietf:params:netconf:base:1.1",
}

// HelloMessage is used when bringing up a NETCONF session
type HelloMessage struct {
	XMLName      xml.Name `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 hello"`
	Capabilities []string `xml:"capabilities>capability"`
	SessionID    int      `xml:"session-id,omitempty"`
}

// Transport interface defines what characterisitics make up a NETCONF transport
// layer object.
type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
	ReceiveHello() (*HelloMessage, error)
	SendHello(*HelloMessage) error
	SetVersion(version string)
}

type transportBasicIO struct {
	io.ReadWriteCloser
	//new add
	version string
}

func (t *transportBasicIO) SetVersion(version string) {
	t.version = version
}

// Sends a well formated NETCONF rpc message as a slice of bytes adding on the
// nessisary framining messages.
func (t *transportBasicIO) Send(data []byte) error {
	var seperator []byte
	var dataInfo []byte
	//headlen := 0
	if t.version == "v1.1" {
		seperator = append(seperator, []byte(msgSeperator_v11)...)
	} else {
		seperator = append(seperator, []byte(msgSeperator)...)
	}

	if t.version == "v1.1" {
		header := fmt.Sprintf("\n#%d\n", len(string(data)))
		dataInfo = append(dataInfo, header...)
		//t.Write([]byte(header))
		//headlen = len([]byte(header))
	}
	dataInfo = append(dataInfo, data...)
	dataInfo = append(dataInfo, seperator...)
	_, err := t.Write(dataInfo)

	return err
}

func (t *transportBasicIO) Receive() ([]byte, error) {
	var seperator []byte
	if t.version == "v1.1" {
		seperator = append(seperator, []byte(msgSeperator_v11)...)
	} else {
		seperator = append(seperator, []byte(msgSeperator)...)
	}
	return t.WaitForBytes([]byte(seperator))
}

func (t *transportBasicIO) SendHello(hello *HelloMessage) error {
	val, err := xml.Marshal(hello)
	if err != nil {
		return err
	}

	header := []byte(xml.Header)
	val = append(header, val...)
	err = t.Send(val)
	return err
}

func (t *transportBasicIO) ReceiveHello() (*HelloMessage, error) {
	hello := new(HelloMessage)

	val, err := t.Receive()
	if err != nil {
		return hello, err
	}

	err = xml.Unmarshal(val, hello)
	return hello, err
}

func (t *transportBasicIO) Writeln(b []byte) (int, error) {
	t.Write(b)
	t.Write([]byte("\n"))
	return 0, nil
}

func (t *transportBasicIO) WaitForFunc(f func([]byte) (int, error)) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 8192)

	pos := 0
	for {
		var n, n1 int
		var err error
		if t.version == "v1.1" {
			var chunkSize int

			// Try to read either the chunk header (incl. chunk size) or the
			// msg seperator.
			// Max is 10 digits, plus two newlines and the hash char.
			const maxHdrLen = 13
			n1, err = io.ReadAtLeast(t.ReadWriteCloser, buf[pos:pos+maxHdrLen], len(msgSeperator_v11))

			if err != nil {
				if err != io.EOF {
					return nil, err
				}
				break
			} else if n1 == len(msgSeperator_v11) && string(buf[pos:pos+n1]) == msgSeperator_v11 {
				n = n1
			} else {
				if n1 < maxHdrLen {
					// Read the rest
					n2, err := io.ReadFull(t.ReadWriteCloser, buf[pos+n1:pos+maxHdrLen])
					if err != nil {
						if err != io.EOF {
							return nil, err
						}
						if n1+n2 != maxHdrLen {
							return nil, fmt.Errorf("Failed to read expected chunk header: %d", maxHdrLen)
						}
					}
					n1 = maxHdrLen
				}
				_, err = fmt.Sscanf(string(buf[pos:pos+maxHdrLen]), "\n#%d\n", &chunkSize)
				if err != nil {
					return nil, err
				}
				numDigits := len(strconv.Itoa(chunkSize))
				var extraChars = maxHdrLen - numDigits - 3
				copy(buf[pos:], buf[pos+numDigits+3:pos+maxHdrLen])

				pos = pos + extraChars

				if pos+chunkSize-extraChars > cap(buf) {
					buf = append(buf, make([]byte, pos+chunkSize-extraChars)...)
				}
				n, err = io.ReadFull(t.ReadWriteCloser, buf[pos:pos+chunkSize-extraChars])

				if n < chunkSize-extraChars {
					// We know the chunk size, so this should only happen if
					// there's a connection error.
					return nil, fmt.Errorf("Failed to read expected chunk size: %d", chunkSize)
				}
			}
		} else {
			n, err = t.Read(buf[pos : pos+(len(buf)/2)])
		}

		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}

		if n > 0 {
			end, err := f(buf[0 : pos+n])
			if err != nil {
				return nil, err
			}

			if end > -1 {
				out.Write(buf[0:end])
				return out.Bytes(), nil
			}

			if pos > 0 {
				out.Write(buf[0:pos])
				copy(buf, buf[pos:pos+n])
			}

			pos = n
		}
	}

	return nil, fmt.Errorf("WaitForFunc failed")
}

func (t *transportBasicIO) WaitForBytes(b []byte) ([]byte, error) {
	return t.WaitForFunc(func(buf []byte) (int, error) {
		return bytes.Index(buf, b), nil
	})
}

func (t *transportBasicIO) WaitForString(s string) (string, error) {
	out, err := t.WaitForBytes([]byte(s))
	if out != nil {
		return string(out), err
	}
	return "", err
}

func (t *transportBasicIO) WaitForRegexp(re *regexp.Regexp) ([]byte, [][]byte, error) {
	var matches [][]byte
	out, err := t.WaitForFunc(func(buf []byte) (int, error) {
		loc := re.FindSubmatchIndex(buf)
		if loc != nil {
			for i := 2; i < len(loc); i += 2 {
				matches = append(matches, buf[loc[i]:loc[i+1]])
			}
			return loc[1], nil
		}
		return -1, nil
	})
	return out, matches, err
}

// ReadWriteCloser represents a combined IO Reader and WriteCloser
type ReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

// NewReadWriteCloser creates a new combined IO Reader and Write Closer from the
// provided objects
func NewReadWriteCloser(r io.Reader, w io.WriteCloser) *ReadWriteCloser {
	return &ReadWriteCloser{r, w}
}
