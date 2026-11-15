package hostinfo

import (
	"net"
	"testing"
)

func TestCollect(t *testing.T) {
	h := Collect()
	if h.OS == "" || h.Arch == "" {
		t.Errorf("OS/Arch missing: %+v", h)
	}
	if h.IPAddresses == nil {
		t.Error("IPAddresses must be an empty slice, not nil")
	}
	if h.MACAddresses == nil {
		t.Error("MACAddresses must be an empty slice, not nil")
	}
	for _, s := range h.IPAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Errorf("invalid IP %q", s)
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("loopback/link-local IP should be filtered: %q", s)
		}
	}
	for _, mac := range h.MACAddresses {
		if _, err := net.ParseMAC(mac); err != nil {
			t.Errorf("invalid MAC %q: %v", mac, err)
		}
	}
}

func TestCollectIPs_IPv4BeforeIPv6(t *testing.T) {
	ips := collectIPs()
	seenIPv6 := false
	for _, s := range ips {
		ip := net.ParseIP(s)
		isV4 := ip != nil && ip.To4() != nil
		if isV4 && seenIPv6 {
			t.Errorf("IPv4 address %q appears after IPv6; want IPv4 first: %v", s, ips)
		}
		if !isV4 {
			seenIPv6 = true
		}
	}
}

func TestIsVirtualInterface(t *testing.T) {
	virtual := []string{"lo", "docker0", "veth123", "br-abc", "vEthernet (WSL)", "tun0", "tailscale0", "VMware Network Adapter VMnet8"}
	for _, name := range virtual {
		if !isVirtualInterface(name) {
			t.Errorf("isVirtualInterface(%q) = false, want true", name)
		}
	}
	physical := []string{"eth0", "enp3s0", "wlan0", "Wi-Fi", "Ethernet", "以太网"}
	for _, name := range physical {
		if isVirtualInterface(name) {
			t.Errorf("isVirtualInterface(%q) = true, want false", name)
		}
	}
}
