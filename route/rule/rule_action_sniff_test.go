package rule

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func newSniffAction(t *testing.T, config string) *RuleActionSniff {
	t.Helper()
	var options option.RuleAction
	require.NoError(t, json.Unmarshal([]byte(config), &options))
	require.Equal(t, C.RuleActionTypeSniff, options.Action)
	action, err := NewRuleAction(log.NewNOPFactory().NewLogger("router"), options)
	require.NoError(t, err)
	return action.(*RuleActionSniff)
}

func TestSniffActionOverridesDestinationWithSniffedDomain(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","sniffer":["tls"],"override_destination":true}`)
	require.True(t, action.OverrideDestination)
	require.Equal(t, "sniff(tls,override_destination)", action.String())

	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	metadata := adapter.InboundContext{Domain: "example.com", Destination: address}
	action.ApplyDestination(&metadata)
	require.Equal(t, M.Socksaddr{Fqdn: "example.com", Port: 443}, metadata.Destination)
	// Packets still addressed to the dialed address are mapped to the name.
	require.Equal(t, address, metadata.RouteOriginalDestination)
}

func TestSniffActionOverrideDropsAddressesResolvedForTheOldDestination(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","override_destination":true}`)
	metadata := adapter.InboundContext{
		Domain:               "b.example",
		Destination:          M.Socksaddr{Fqdn: "a.example", Port: 443},
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.7")},
	}
	action.ApplyDestination(&metadata)
	require.Equal(t, M.Socksaddr{Fqdn: "b.example", Port: 443}, metadata.Destination)
	require.Empty(t, metadata.DestinationAddresses)
	require.Equal(t, M.Socksaddr{Fqdn: "a.example", Port: 443}, metadata.RouteOriginalDestination)
	// A name replacing a name leaves no dialed address behind.
	require.False(t, metadata.OverriddenAddress.IsValid())

	// The same name again changes nothing, and keeps its resolved addresses.
	same := adapter.InboundContext{
		Domain:               "b.example",
		Destination:          M.Socksaddr{Fqdn: "b.example", Port: 443},
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.8")},
	}
	action.ApplyDestination(&same)
	require.Len(t, same.DestinationAddresses, 1)
	require.False(t, same.RouteOriginalDestination.IsValid())
}

func TestSniffActionOverrideKeepsAddressesOutsideThePublicInternet(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","override_destination":true}`)
	// The local network, loopback, link-local, tailnet and carrier addresses, multicast.
	for _, address := range []string{
		"192.168.1.10", "10.0.2.2", "127.0.0.1", "169.254.1.1", "100.101.102.103",
		"::ffff:100.64.0.1", "fd7a:115c:a1e0::1", "fe80::1", "239.255.255.250",
	} {
		destination := M.ParseSocksaddrHostPort(address, 443)
		metadata := adapter.InboundContext{Domain: "nas.example", Destination: destination}
		action.ApplyDestination(&metadata)
		require.Equal(t, destination, metadata.Destination, address)
		require.False(t, metadata.OverriddenAddress.IsValid(), address)
	}
}

func TestAddressRulesMatchTheAddressAConnectionByNameWasDialedTo(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","override_destination":true}`)
	rule, err := NewIPCIDRItem(false, []string{"203.0.113.0/24"})
	require.NoError(t, err)

	metadata := adapter.InboundContext{Domain: "example.com", Destination: M.ParseSocksaddrHostPort("203.0.113.7", 443)}
	action.ApplyDestination(&metadata)
	require.True(t, metadata.Destination.IsFqdn())
	require.Equal(t, netip.MustParseAddr("203.0.113.7"), metadata.OverriddenAddress)
	require.True(t, rule.Match(&metadata))

	// Once the name is resolved, address rules see what it resolved to.
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	require.False(t, rule.Match(&metadata))
}

func TestSniffActionKeepsDestinationWithoutOverride(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff"}`)
	require.False(t, action.OverrideDestination)
	require.Equal(t, "sniff", action.String())

	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	metadata := adapter.InboundContext{Domain: "example.com", Destination: address}
	action.ApplyDestination(&metadata)
	require.Equal(t, address, metadata.Destination)
}

func TestSniffActionOverrideIgnoresNamesThatAreNotDomains(t *testing.T) {
	t.Parallel()

	action := newSniffAction(t, `{"action":"sniff","timeout":"1s","override_destination":true}`)
	require.Equal(t, "sniff(1s,override_destination)", action.String())
	address := M.ParseSocksaddrHostPort("192.0.2.7", 443)
	// No sniffed name, and an address in place of a name: the dialed address stays.
	for _, domain := range []string{"", "198.51.100.1"} {
		metadata := adapter.InboundContext{Domain: domain, Destination: address}
		action.ApplyDestination(&metadata)
		require.Equal(t, address, metadata.Destination, domain)
	}
}
