package protocol

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/favonia/cloudflare-ddns/internal/ipnet"
	"github.com/favonia/cloudflare-ddns/internal/pp"
)

// LocalWithSuffix detects the IP address by choosing the first "good" IP
// address assigned to a network interface.
type LocalWithSuffix struct {
	// Name of the detection protocol.
	ProviderName string

	// The suffix that the chosen IP is suppesed to have.
	Suffix string
}

// Name of the detection protocol.
func (p LocalWithSuffix) Name() string {
	return p.ProviderName
}

const (
	digits  = "0123456789abcdef"
	maxsize = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
)

func expandSuffix(suffix string) (string, bool) {
	suf := suffix
	i := strings.Index(suf, "%")
	if i != -1 { // strip zone suffix
		suf = suf[:i]
	}
	ret := make([]byte, 0, maxsize)

	slices := strings.Split(suf, ":")
	for i, ashex := range slices {
		x, err := strconv.ParseUint(ashex, 16, 16)
		if err != nil {
			return "", false
		}
		if i > 0 {
			ret = append(ret, ':')
		}
		ret = append(ret, digits[x>>12], digits[x>>8&0xf], digits[x>>4&0xf], digits[x&0xf])
	}

	return string(ret), true
}

func HasSuffix(ip netip.Addr, suffix string) bool {
	return strings.HasSuffix(ip.StringExpanded(), suffix)
}

// ExtractAddr converts an address from [net.Addr] to [netip.Addr].
// The address will be unmapped.
func ExtractAddr(addr net.Addr) (netip.Addr, bool) {
	switch v := addr.(type) {
	case *net.IPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return ip.Unmap().WithZone(v.Zone), true
	case *net.IPNet:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return ip.Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// SelectIPWithSuffix takes a list of [net.Addr] and choose the first matching IP (if any).
func SelectIPWithSuffix(ipNet ipnet.Type, addrs []net.Addr, suffix string) (netip.Addr, bool) {
	for _, addr := range addrs {
		ip, ok := ExtractAddr(addr)
		if !ok {
			continue
		}
		if ipNet.Matches(ip) && HasSuffix(ip, suffix) &&
			ip.IsGlobalUnicast() && !ip.IsPrivate() { // IsGlobalUnicast also considers private as "global unicast"
			return ip, true
		}
	}

	return netip.Addr{}, false
}

// GetIP detects the IP address by pretending to send an UDP packet.
// (No actual UDP packets will be sent out.)
func (p LocalWithSuffix) GetIP(_ context.Context, ppfmt pp.PP, ipNet ipnet.Type) (netip.Addr, Method, bool) {
	if ipNet != ipnet.IP6 {
		ppfmt.Noticef(pp.EmojiUserError, "Provider %s can only be used for IPv6", p.ProviderName)
		return netip.Addr{}, MethodUnspecified, false
	}

	suffix, ok := expandSuffix(p.Suffix)
	if !ok {
		ppfmt.Noticef(pp.EmojiUserError, "Failed to parse suffix %s", p.Suffix)
		return netip.Addr{}, MethodUnspecified, false
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		ppfmt.Noticef(pp.EmojiUserError, "Failed to get interfaces: %v", err)
		return netip.Addr{}, MethodUnspecified, false
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			ppfmt.Noticef(pp.EmojiImpossible, "Failed to list addresses of interface %s: %v", iface.Name, err)
			continue
		}

		ip, ok := SelectIPWithSuffix(ipNet, addrs, suffix)
		if ok {
			return ip, MethodPrimary, ok
		}
	}

	ppfmt.Noticef(pp.EmojiError,
		"Failed to find any global unicast %s address with expanded suffix %s",
		ipNet.Describe(), suffix)
	return netip.Addr{}, MethodUnspecified, false
}
