package agent

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"time"
)

func controllerIngressTargeted(origin string, p *Policy) bool {
	parsed, e := url.Parse(origin)
	if e != nil {
		return true
	}
	port := 443
	if parsed.Port() != "" {
		port, e = strconv.Atoi(parsed.Port())
		if e != nil {
			return true
		}
	}
	targeted := false
	for _, svc := range p.Services {
		mode := svc.Mode
		if mode == "" {
			mode = p.Mode
		}
		if mode == "enforce" && svc.Protocol == "tcp" && svc.Port == port {
			targeted = true
		}
	}
	if !targeted {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", parsed.Hostname())
	if e != nil {
		return true
	}
	addresses, e := net.InterfaceAddrs()
	if e != nil {
		return true
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
		for _, address := range addresses {
			local, _, e := net.ParseCIDR(address.String())
			if e == nil && local.Equal(net.IP(ip.AsSlice())) {
				return true
			}
		}
	}
	return false
}
