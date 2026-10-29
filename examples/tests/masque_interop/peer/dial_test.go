//go:build unix

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

const testProtocol = "dial-test"

func testServerTLS(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{testProtocol},
	}
}

// reusingBind binds addr with SO_REUSEADDR and SO_REUSEPORT, as a process sharing the host may.
func reusingBind(addr string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if err == nil {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
		}); e != nil {
			return e
		}
		return err
	}}
	return config.ListenPacket(context.Background(), "udp", addr)
}

// The client socket is bound to its exact local address, so no other socket can take over
// its port and with it the server's answers, and it is released with the connection.
func TestDialQUICOwnsItsExactLocalEndpoint(t *testing.T) {
	listener, err := quic.ListenAddr("127.0.0.1:0", testServerTLS(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialQUIC(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{testProtocol}}, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	if local.IP.IsUnspecified() {
		t.Fatalf("bound to a wildcard address: %v", local)
	}
	if thief, err := reusingBind(local.String()); err == nil {
		thief.Close()
		t.Fatalf("another socket could bind %v", local)
	}

	if err := conn.CloseWithError(0, "done"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		released, err := net.ListenUDP("udp", local)
		if err == nil {
			released.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%v still held after close: %v", local, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
