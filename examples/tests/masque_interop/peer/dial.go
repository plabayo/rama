package main

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

// dialQUIC dials addr like quic.DialAddr, but from a UDP socket bound to the exact local
// address that reaches it. A wildcard socket's port can be taken over by a later, more
// specific bind with SO_REUSEADDR or SO_REUSEPORT, as BSD and macOS allow, which then
// receives every answer: on a shared host that stalls the handshake.
func dialQUIC(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	route, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	local := route.LocalAddr().(*net.UDPAddr)
	route.Close()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: socket}
	conn, err := transport.Dial(ctx, remote, tlsConf, conf)
	if err != nil {
		transport.Close()
		socket.Close()
		return nil, err
	}
	// The socket is this connection's alone, as with quic.DialAddr.
	go func() {
		<-conn.Context().Done()
		transport.Close()
		socket.Close()
	}()
	return conn, nil
}
