// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func (mb *tcpServerTransporter) AssignConn(conn net.Conn) {
	mb.Conn = conn
}

func (mb *tcpServerTransporter) waitConnect() error {
	mb.logf("listen on: %s", mb.Address)

	if mb.listener == nil {
		ln, err := net.Listen("tcp", mb.Address)
		if err != nil {
			return err
		}
		mb.listener = ln
	}

	conn, err := mb.listener.Accept()
	if err != nil {
		return err
	}
	mb.logf("new connection: %s", conn.RemoteAddr())

	mb.Conn = conn
	return nil
}

// TCPServerHandler implements Packager and Transporter interface.
type TCPServerHandler struct {
	tcpPackager
	tcpServerTransporter
}

// NewTCPServerHandler allocates a new TCPServerHandler.
func NewTCPServerHandler(address string) *TCPServerHandler {
	h := &TCPServerHandler{}
	h.Address = address
	h.Timeout = tcpTimeout
	h.IdleTimeout = tcpIdleTimeout
	return h
}

// TCPServer creates TCP client with default handler and given connect string.
func TCPServer(address string) Client {
	handler := NewTCPServerHandler(address)
	return NewClient(handler)
}

// tcpTransporter implements Transporter interface.
type tcpServerTransporter struct {
	// Connect string
	Address string
	// Connect & Read timeout
	Timeout time.Duration
	// Idle timeout to close the connection
	IdleTimeout time.Duration
	// Transmission logger
	Logger *log.Logger

	// TCP connection
	mu           sync.Mutex
	Conn         net.Conn
	closeTimer   *time.Timer
	lastActivity time.Time

	RegMsg string

	//RtuOverTCP
	// RtuOverTCPtp bool //TODO: How to get tcpPackager's flag?

	// AsciiOverTCPtp bool

	ListenMode bool

	ChannelTypeTp string
	TransModeTp   string

	DeviceID string

	listener net.Listener
}

// Send sends data to server and ensures response length is greater than header length.
func (mb *tcpServerTransporter) Send(aduRequest []byte) (aduResponse []byte, err error) {

	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Establish a new connection if not connected
	if err = mb.connect(); err != nil {
		return
	}

	// Set timer to close when idle
	mb.lastActivity = time.Now()
	mb.startCloseTimer()
	// Set write and read timeout
	var timeout time.Time
	if mb.Timeout > 0 {
		timeout = mb.lastActivity.Add(mb.Timeout)
	}
	if err = mb.Conn.SetDeadline(timeout); err != nil {
		return
	}

	if mb.ListenMode {
		mb.logf("fake send % x", aduRequest)
	} else {
		// Send data
		mb.logf("sending % x", aduRequest)
		if _, err = mb.Conn.Write(aduRequest); err != nil {
			if netError, ok := err.(net.Error); ok && netError.Timeout() == false {
				mb.close()
			}
			return
		}
	}

	if mb.TransModeTp == RTU {
		function := aduRequest[1]
		functionFail := aduRequest[1] & 0x80
		bytesToRead := calculateResponseLength(aduRequest)

		var n int
		var n1 int
		var data [rtuMaxSize]byte
		//We first read the minimum length and then read either the full package
		//or the error package, depending on the error status (byte 2 of the response)
		//if n, err = io.ReadFull(mb.Conn, data[:rtuMinSize]); err != nil {
		//	return
		//}
		if n, err = mb.Conn.Read(data[:]); err != nil {
			return
		}
		//if the function is correct
		if data[1] == function {
			//we read the rest of the bytes
			if n < bytesToRead {
				if bytesToRead > rtuMinSize && bytesToRead <= rtuMaxSize {
					if bytesToRead > n {
						n1, err = io.ReadFull(mb.Conn, data[n:bytesToRead])
						n += n1
					}
				}
			}
		} else if data[1] == functionFail {
			//for error we need to read 5 bytes
			if n < rtuExceptionSize {
				n1, err = io.ReadFull(mb.Conn, data[n:rtuExceptionSize])
			}
			n += n1
		}

		if err != nil {
			return
		}
		aduResponse = data[:n]
		mb.logf("modbus: received % x\n", aduResponse)
		return
	} else if mb.TransModeTp == ASCII {
		// Get the response
		var n int
		var data [asciiMaxSize]byte
		length := 0
		for {
			if n, err = io.ReadFull(mb.Conn, data[length:length+1]); err != nil {
				return
			}
			length += n
			if length >= asciiMaxSize || n == 0 {
				break
			}
			// Expect end of frame in the data received
			if length > asciiMinSize {
				if string(data[length-len(asciiEnd):length]) == asciiEnd {
					break
				}
			}
		}
		aduResponse = data[:length]
		mb.logf("modbus: received %q\n", aduResponse)
		return
	} else {
		// Read header first
		var data [tcpMaxLength]byte
		if _, err = io.ReadFull(mb.Conn, data[:tcpHeaderSize]); err != nil {
			return
		}
		// Read length, ignore transaction & protocol id (4 bytes)
		length := int(binary.BigEndian.Uint16(data[4:]))
		if length <= 0 {
			mb.flush(data[:])
			err = fmt.Errorf("modbus: length in response header '%v' must not be zero", length)
			return
		}
		if length > (tcpMaxLength - (tcpHeaderSize - 1)) {
			mb.flush(data[:])
			err = fmt.Errorf("modbus: length in response header '%v' must not greater than '%v'", length, tcpMaxLength-tcpHeaderSize+1)
			return
		}
		// Skip unit id
		length += tcpHeaderSize - 1
		if _, err = io.ReadFull(mb.Conn, data[tcpHeaderSize:length]); err != nil {
			return
		}
		aduResponse = data[:length]
		mb.logf("modbus: received % x\n", aduResponse)
		return
	}
}

// Connect establishes a new connection to the address in Address.
// Connect and Close are exported so that multiple requests can be done with one session
func (mb *tcpServerTransporter) Connect() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	return mb.connect()
}

func (mb *tcpServerTransporter) connect() error {
	if mb.Conn == nil {
		return errors.New("disconnect")
	}
	return nil
}

func (mb *tcpServerTransporter) startCloseTimer() {
	if mb.IdleTimeout <= 0 {
		return
	}
	if mb.closeTimer == nil {
		mb.closeTimer = time.AfterFunc(mb.IdleTimeout, mb.closeIdle)
	} else {
		mb.closeTimer.Reset(mb.IdleTimeout)
	}
}

// Close closes current connection.
func (mb *tcpServerTransporter) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	return mb.close()
}

// flush flushes pending data in the connection,
// returns io.EOF if connection is closed.
func (mb *tcpServerTransporter) flush(b []byte) (err error) {
	if err = mb.Conn.SetReadDeadline(time.Now()); err != nil {
		return
	}
	// Timeout setting will be reset when reading
	if _, err = mb.Conn.Read(b); err != nil {
		// Ignore timeout error
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			err = nil
		}
	}
	return
}

// Flush flushes pending data in the connection,
// returns io.EOF if connection is closed.
func (mb *tcpServerTransporter) Flush() (err error) {
	var b [tcpMaxLength]byte
	if err = mb.Conn.SetReadDeadline(time.Now()); err != nil {
		return
	}
	// Timeout setting will be reset when reading
	if _, err = mb.Conn.Read(b[:]); err != nil {
		// Ignore timeout error
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			err = nil
		}
	}
	return
}

func (mb *tcpServerTransporter) logf(format string, v ...interface{}) {
	if mb.Logger != nil {
		mb.Logger.Printf(format, v...)
	}
}

// closeLocked closes current connection. Caller must hold the mutex before calling this method.
func (mb *tcpServerTransporter) close() (err error) {
	if mb.Conn != nil {
		err = mb.Conn.Close()
		mb.Conn = nil
	}
	return
}

// closeIdle closes the connection if last activity is passed behind IdleTimeout.
func (mb *tcpServerTransporter) closeIdle() {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if mb.IdleTimeout <= 0 {
		return
	}
	idle := time.Now().Sub(mb.lastActivity)
	if idle >= mb.IdleTimeout {
		mb.logf("modbus: closing connection due to idle timeout: %v", idle)
		mb.close()
	}
}
