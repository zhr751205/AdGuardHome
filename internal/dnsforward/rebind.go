// DNS Rebinding protection

package dnsforward

import (
	"net"
	"strings"

	"github.com/AdguardTeam/golibs/log"
)

type dnsRebindChecker struct {
}

// IsPrivate reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
func (*dnsRebindChecker) isPrivate(ip net.IP) bool {
	//TODO: remove once https://github.com/golang/go/pull/42793 makes it to stdlib
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

func (c *dnsRebindChecker) isRebindHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return c.isRebindIP(ip)
	}

	return host == "localhost"
}

func (c *dnsRebindChecker) isRebindIP(ip net.IP) bool {
	// This is compatible with dnsmasq definition
	// See: https://github.com/imp/dnsmasq/blob/4e7694d7107d2299f4aaededf8917fceb5dfb924/src/rfc1035.c#L412

	rebind := false
	if ip4 := ip.To4(); ip4 != nil {

		/* 0.0.0.0/8 (RFC 5735 section 3. "here" network) */
		rebind = ip4[0] == 0 ||

			/* 10.0.0.0/8     (private)  */
			ip4[0] == 10 ||

			/* 172.16.0.0/12  (private)  */
			(ip4[0] == 172 && ip4[1]&0x10 == 0x10) ||

			/* 169.254.0.0/16 (zeroconf) */
			(ip4[0] == 169 && ip4[1] == 254) ||

			/* 192.0.2.0/24   (test-net) */
			(ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||

			/* 198.51.100.0/24(test-net) */
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||

			/* 203.0.113.0/24 (test-net) */
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) ||

			/* 255.255.255.255/32 (broadcast)*/
			ip4.Equal(net.IPv4bcast)
	} else {
		rebind = ip.Equal(net.IPv6zero) || ip.Equal(net.IPv6unspecified) ||
			ip.Equal(net.IPv6interfacelocalallnodes) ||
			ip.Equal(net.IPv6linklocalallnodes) ||
			ip.Equal(net.IPv6linklocalallrouters)
	}

	return rebind || c.isPrivate(ip) || ip.IsLoopback()
}

// Checks DNS rebinding attacks
// Note both whitelisted and cached hosts will bypass rebinding check (see: processFilteringAfterResponse()).
func (s *Server) isResponseRebind(domain, host string) bool {
	if !s.conf.RebindingEnabled {
		return false
	}

	if log.GetLevel() >= log.DEBUG {
		timer := log.StartTimer()
		defer timer.LogElapsed("DNS Rebinding check for %s -> %s", domain, host)
	}

	for _, h := range s.conf.RebindingAllowedHosts {
		if strings.HasSuffix(domain, h) {
			return false
		}
	}

	c := dnsRebindChecker{}
	return c.isRebindHost(host)
}
