//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// REALITY builds its uTLS connection in ClientHandshake, so it needs the same wrap gate as
// UTLSClientConfig.Client to honor fragment and record_fragment.
func TestRealityClient_FragmentConn(t *testing.T) {
	t.Parallel()
	for _, gate := range []struct{ fragment, recordFragment, wraps bool }{
		{false, false, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	} {
		client, server := net.Pipe()
		config := &RealityClientConfig{uClient: newUTLSClientConfigForGateTest(gate.fragment, gate.recordFragment)}
		_, isTF := config.fragmentConn(client).(*tf.Conn)
		require.Equal(t, gate.wraps, isTF, "fragment=%v record_fragment=%v", gate.fragment, gate.recordFragment)
		client.Close()
		server.Close()
	}
}

// The handshake writes its ClientHello through the wrap: in several writes for fragment and in
// several TLS records for record_fragment.
func TestRealityClient_HandshakeFragmentsClientHello(t *testing.T) {
	t.Parallel()
	for _, gate := range []struct{ fragment, recordFragment bool }{
		{false, false},
		{true, false},
		{false, true},
		{true, true},
	} {
		config, err := NewRealityClient(context.Background(), logger.NOP(), "www.example.com", option.OutboundTLSOptions{
			Enabled:               true,
			ServerName:            "www.example.com",
			Fragment:              gate.fragment,
			RecordFragment:        gate.recordFragment,
			FragmentFallbackDelay: badoption.Duration(time.Millisecond),
			UTLS:                  &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality:               &option.OutboundRealityOptions{Enabled: true, PublicKey: "yAnz5TF-lXXJte14tji3zlMNq-hd2rYUIgJBgB3fBmk", ShortID: "ab"},
		})
		require.NoError(t, err)
		client, server := net.Pipe()
		// A failed read must still release the handshake goroutine.
		t.Cleanup(func() {
			client.Close()
			server.Close()
		})
		go config.(*RealityClientConfig).ClientHandshake(context.Background(), client)
		writes, records := readClientHello(t, server)
		client.Close()
		server.Close()
		require.Equal(t, gate.fragment, writes > 1, "fragment=%v record_fragment=%v: %d writes", gate.fragment, gate.recordFragment, writes)
		require.Equal(t, gate.recordFragment, records > 1, "fragment=%v record_fragment=%v: %d records", gate.fragment, gate.recordFragment, records)
	}
}

// readClientHello reads one ClientHello and returns how many writes and TLS records carried it.
// Each read of a net.Pipe returns the data of one write.
func readClientHello(t *testing.T, conn net.Conn) (writes int, records int) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var data, payload []byte
	buffer := make([]byte, 1<<16)
	for {
		n, err := conn.Read(buffer)
		require.NoError(t, err)
		writes++
		data = append(data, buffer[:n]...)
		for len(data) >= 5 && len(data) >= 5+int(binary.BigEndian.Uint16(data[3:5])) {
			length := int(binary.BigEndian.Uint16(data[3:5]))
			payload = append(payload, data[5:5+length]...)
			data = data[5+length:]
			records++
		}
		// The handshake message header gives the length of the whole ClientHello.
		if len(payload) >= 4 && len(payload) >= 4+(int(payload[1])<<16|int(payload[2])<<8|int(payload[3])) {
			return writes, records
		}
	}
}
