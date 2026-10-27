package route

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestAddressOverrideReplacesTheAddressASniffedNameWasDialedTo(t *testing.T) {
	t.Parallel()

	rule, err := R.NewIPCIDRItem(false, []string{"203.0.113.0/24"})
	require.NoError(t, err)
	// What a sniff action leaves after sending a connection to 203.0.113.7 on by its name.
	metadata := adapter.InboundContext{
		Destination:       M.Socksaddr{Fqdn: "example.com", Port: 443},
		OverriddenAddress: netip.MustParseAddr("203.0.113.7"),
	}
	require.True(t, rule.Match(&metadata))

	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{OverrideAddress: M.ParseSocksaddrHostPort("other.example", 0)})
	require.Equal(t, M.Socksaddr{Fqdn: "other.example", Port: 443}, metadata.Destination)
	require.False(t, metadata.OverriddenAddress.IsValid())
	require.False(t, rule.Match(&metadata))
}
