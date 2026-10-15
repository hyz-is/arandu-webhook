package webhook

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	httpclient "github.com/arandu-io/hesape/http/client"
)

// sharedAddressSpace is 100.64.0.0/10, the carrier-grade NAT range of RFC
// 6598. It is global unicast to the standard library, so hesape's guard lets
// it through, and it is where a cluster's or a tailnet's own machines answer.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// refusedAddress reports whether a delivery may not connect to the address:
// loopback, private, link-local, multicast, unspecified, or in the shared
// address space.
func refusedAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsGlobalUnicast() || addr.IsPrivate() || sharedAddressSpace.Contains(addr)
}

// newDeliveryClient is the client the deliveries go out on.
//
// A client the application gave keeps its transport, wrapped in hesape's
// guard, which settles the scheme and caps the answer on every hop. Without
// one, the transport is a copy of hesape's guarded one, with no proxy -- a
// delivery goes to the address it names -- and a dialer in front of hesape's
// that resolves the host itself, refuses the whole answer when any address is
// refused, and hands hesape's dialer the address it checked, which checks it
// again as it connects. Nothing is resolved twice, so a name that answers
// differently the second time reaches nothing it was not checked for.
func newDeliveryClient(custom *http.Client) (*http.Client, error) {
	if custom != nil {
		return httpclient.NewFactory(custom).CreatePendingRequest().CreateClient(nil), nil
	}
	base, ok := httpclient.NewFactory(nil).CreatePendingRequest().BuildClient().Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("webhook: hesape's client has no transport to guard")
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.DialContext = publicDialer(transport.DialContext, net.DefaultResolver)
	return httpclient.NewFactory(&http.Client{Transport: transport}).CreatePendingRequest().CreateClient(nil), nil
}

// resolver is the one method of net.Resolver the dialer needs.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// publicDialer resolves the host, refuses it when any of its addresses is
// refused, and dials the addresses it checked through next.
func publicDialer(next func(context.Context, string, string) (net.Conn, error), names resolver) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not an address", httpclient.ErrInternalAddress, address)
		}
		var addrs []netip.Addr
		if literal, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{literal}
		} else if addrs, err = names.LookupNetIP(ctx, "ip", host); err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("webhook: %s resolves to no address", host)
		}
		for _, addr := range addrs {
			if refusedAddress(addr) {
				return nil, fmt.Errorf("%w: %s resolves to %s", httpclient.ErrInternalAddress, host, addr)
			}
		}
		var failures error
		for _, addr := range addrs {
			conn, err := next(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			failures = errors.Join(failures, err)
		}
		return nil, failures
	}
}
