package modbus

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// LoadCertPoolFromFile loads a certificate store from a file into a CertPool object.
func LoadCertPoolFromFile(filePath string) (*x509.CertPool, error) {
	// read the entire cert store, which may contain zero, one or more certificates
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("%v: empty file", filePath)
	}
	return LoadCertPool(bytes.NewReader(buf))
}

// LoadCertPool loads certificates from given io.Reader and returns the CertPool.
// It returns and error when certificates are missing.
func LoadCertPool(r io.Reader) (*x509.CertPool, error) {
	buf := &bytes.Buffer{}
	io.Copy(buf, r)
	if buf.Len() == 0 {
		return nil, errors.New("no certs")
	}
	// add certs to the pool
	cp := x509.NewCertPool()
	if ok := cp.AppendCertsFromPEM(buf.Bytes()); !ok {
		return nil, errors.New("failed to parse and load certificates")
	}
	return cp, nil
}

// tlsSockWrapper wraps a TLS socket to work around odd error handling in
// TLSConn on internal connection state corruption.
// tlsSockWrapper implements the net.Conn interface to allow its
// use by the modbus TCP transport.
type tlsSockWrapper struct {
	sock net.Conn
}

func newTLSSockWrapper(sock net.Conn) *tlsSockWrapper {
	return &tlsSockWrapper{
		sock: sock,
	}
}

func (tsw *tlsSockWrapper) Read(buf []byte) (int, error) {
	return tsw.sock.Read(buf)
}

func (tsw *tlsSockWrapper) Write(buf []byte) (int, error) {
	wlen, err := tsw.sock.Write(buf)
	if err != nil && os.IsTimeout(err) {
		// since write timeouts corrupt the internal state of TLS sockets,
		// any subsequent read/write operation will fail and return the same write
		// timeout error (see https://pkg.go.dev/crypto/tls#Conn.SetWriteDeadline).
		// this isn't all that helpful to clients, which may be tricked into
		// retrying forever, treating timeout errors as transient.
		// to avoid this, close the TLS socket after the first write timeout.
		// this ensures that clients 1) get a timeout error on the first write timeout
		// and 2) get an ErrNetClosing "use of closed network connection" on subsequent
		// operations.
		tsw.sock.Close()
	}
	return wlen, nil
}

func (tsw *tlsSockWrapper) Close() error {
	return tsw.sock.Close()
}

func (tsw *tlsSockWrapper) SetDeadline(deadline time.Time) error {
	return tsw.sock.SetDeadline(deadline)
}

func (tsw *tlsSockWrapper) SetReadDeadline(deadline time.Time) error {
	return tsw.sock.SetReadDeadline(deadline)
}

func (tsw *tlsSockWrapper) SetWriteDeadline(deadline time.Time) error {
	return tsw.sock.SetWriteDeadline(deadline)
}

func (tsw *tlsSockWrapper) LocalAddr() net.Addr {
	return tsw.sock.LocalAddr()
}

func (tsw *tlsSockWrapper) RemoteAddr() net.Addr {
	return tsw.sock.RemoteAddr()
}
