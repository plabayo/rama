// Independent RFC 9484 peer. Packet I/O is in memory; no TUN or route changes.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

var clientPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::1/128")}
var routes = []connectip.IPRoute{
	{StartIP: netip.MustParseAddr("192.0.2.2"), EndIP: netip.MustParseAddr("192.0.2.2")},
	{StartIP: netip.MustParseAddr("2001:db8::2"), EndIP: netip.MustParseAddr("2001:db8::2")},
}

func main() {
	mode := flag.String("mode", "", "server or client")
	cert := flag.String("cert", "", "test certificate PEM")
	key := flag.String("key", "", "test private key PEM (server only)")
	endpoint := flag.String("url", "", "fixed CONNECT-IP endpoint (client only)")
	packets := flag.String("packets", "", "JSON array of hex IP packets (client only)")
	flag.Parse()
	// A stalled peer fails the fixture, even when an API has no context argument.
	time.AfterFunc(45*time.Second, func() { log.Fatal("CONNECT-IP peer deadline") })
	if *mode == "server" {
		serve(*cert, *key)
		return
	}
	if *mode == "client" {
		if err := dial(*cert, *endpoint, *packets); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Fatal("expected -mode server|client")
}

func serve(certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	address := socket.LocalAddr().(*net.UDPAddr)
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/vpn", address.Port))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := connectip.ParseProxyRequest(r, template)
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		proxy := connectip.Proxy{}
		conn, err := proxy.Proxy(w, req)
		if err != nil {
			log.Print(err)
			return
		}
		defer conn.Close()
		if err = conn.AssignAddresses(clientPrefixes); err != nil {
			log.Print(err)
			return
		}
		if err = conn.AdvertiseRoute(routes); err != nil {
			log.Print(err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		requested, err := conn.ReceiveAddressRequest(ctx)
		if err != nil {
			log.Print(err)
			return
		}
		if len(requested.Prefixes) != 2 {
			log.Print("expected two address requests")
			return
		}
		if err = requested.Respond(clientPrefixes, nil); err != nil {
			log.Print(err)
			return
		}
		buffer := make([]byte, 65575)
		for i := 0; i < 2; i++ {
			n, err := conn.ReadPacket(buffer)
			if err != nil {
				log.Print(err)
				return
			}
			reply, err := reverse(buffer[:n], 64)
			if err != nil {
				log.Print(err)
				return
			}
			icmp, err := conn.WritePacket(reply)
			if err != nil || len(icmp) != 0 {
				log.Printf("write: %v ICMP=%x", err, icmp)
				return
			}
		}
		if err = conn.AdvertiseRoute(nil); err != nil {
			log.Print(err)
			return
		}
		// Wait for the client to close, keeping the final control update available.
		_, _ = conn.ReadPacket(buffer)
	})
	server := http3.Server{Handler: handler, TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}), EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1400}}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"address": address.String()})
	if err := server.Serve(socket); err != nil {
		log.Fatal(err)
	}
}

func dial(certFile, endpoint, packetFile string) error {
	pem, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid trust anchor")
	}
	raw, err := os.ReadFile(packetFile)
	if err != nil {
		return err
	}
	var values []string
	if err = json.Unmarshal(raw, &values); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := connectip.NewRequest(ctx, uritemplate.MustNew(endpoint))
	if err != nil {
		return err
	}
	transport := connectip.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, NextProtos: []string{"h3"}}, QUICConfig: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1400}}
	conn, _, err := transport.Dial(request)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ReceiveAddressAssignment(ctx); err != nil {
		return err
	}
	advertised, err := conn.Routes(ctx)
	if err != nil || len(advertised) == 0 {
		return fmt.Errorf("initial routes: %v %v", advertised, err)
	}
	ids, err := conn.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("::/128")})
	if err != nil {
		return err
	}
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		return err
	}
	if len(assigned) != 2 || assigned[0].RequestID != ids[0] || assigned[1].RequestID != ids[1] {
		return fmt.Errorf("request IDs not echoed: %v", assigned)
	}
	buffer := make([]byte, 65575)
	for _, value := range values {
		packet, err := hex.DecodeString(value)
		if err != nil {
			return err
		}
		expected, err := reverse(packet, 64)
		if err != nil {
			return err
		}
		icmp, err := conn.WritePacket(packet)
		if err != nil || len(icmp) != 0 {
			return fmt.Errorf("write: %v, ICMP=%x", err, icmp)
		}
		n, err := conn.ReadPacket(buffer)
		if err != nil {
			return err
		}
		if !bytes.Equal(buffer[:n], expected) {
			return fmt.Errorf("packet mismatch: got %x want %x", buffer[:n], expected)
		}
	}
	withdrawn, err := conn.Routes(ctx)
	if err != nil || len(withdrawn) != 0 {
		return fmt.Errorf("route withdrawal: %v %v", withdrawn, err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "packets": len(values), "address_requests": len(ids), "routes_withdrawn": true})
}

// A local test responder creates a packet with reversed addresses and fresh TTL.
// connect-ip-go decrements TTL during WritePacket; the Rust oracle accounts for it.
func reverse(packet []byte, ttl byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, fmt.Errorf("empty packet")
	}
	out := append([]byte(nil), packet...)
	switch out[0] >> 4 {
	case 4:
		if len(out) < 20 {
			return nil, fmt.Errorf("short IPv4")
		}
		copy(out[12:16], packet[16:20])
		copy(out[16:20], packet[12:16])
		out[8] = ttl
		out[10] = 0
		out[11] = 0
		length := int(out[0]&15) * 4
		if length > len(out) {
			return nil, fmt.Errorf("short IPv4 options")
		}
		var sum uint32
		for i := 0; i < length; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(out[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(out[10:12], ^uint16(sum))
	case 6:
		if len(out) < 40 {
			return nil, fmt.Errorf("short IPv6")
		}
		copy(out[8:24], packet[24:40])
		copy(out[24:40], packet[8:24])
		out[7] = ttl
	default:
		return nil, fmt.Errorf("invalid version")
	}
	return out, nil
}
