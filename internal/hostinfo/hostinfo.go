// Package hostinfo collects endpoint identity details for the report and the
// machine-readable inventory.
package hostinfo

import (
	"net"
	"os"
	"runtime"
	"sort"
	"strings"

	"sys-scanner/internal/types"
)

// Collect returns the endpoint hostname, OS, architecture, non-loopback IP
// addresses, and hardware MAC addresses.
func Collect() types.HostInfo {
	hostname, _ := os.Hostname()
	return types.HostInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		IPAddresses:  collectIPs(),
		MACAddresses: collectMACs(),
	}
}

// collectIPs returns unique, non-loopback, non-link-local interface addresses.
// Virtual/container/VPN interfaces are skipped. IPv4 addresses are listed
// before IPv6 addresses.
func collectIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}

	seen := make(map[string]struct{})
	ips := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 || isVirtualInterface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			ips = append(ips, s)
		}
	}

	sort.SliceStable(ips, func(i, j int) bool {
		vi := net.ParseIP(ips[i])
		vj := net.ParseIP(ips[j])
		ii := vi != nil && vi.To4() != nil
		ij := vj != nil && vj.To4() != nil
		if ii != ij {
			return ii
		}
		return ips[i] < ips[j]
	})
	return ips
}

// collectMACs returns unique hardware addresses from non-loopback physical
// interfaces.
func collectMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}

	seen := make(map[string]struct{})
	macs := make([]string, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || isVirtualInterface(ifc.Name) {
			continue
		}
		hw := ifc.HardwareAddr
		if len(hw) < 6 {
			continue
		}
		mac := strings.ToLower(hw.String())
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		macs = append(macs, mac)
	}

	sort.Strings(macs)
	return macs
}

// isVirtualInterface filters container, VM, tunnel and VPN adapters so the
// report shows the endpoint's physical network identity rather than a dozen
// Docker/veth addresses.
func isVirtualInterface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if n == "lo" {
		return true
	}
	markers := []string{
		"docker", "veth", "br-", "virbr", "vmnet", "vboxnet",
		"tun", "tap", "wireguard", "tailscale", "zerotier",
		"vethernet", "wsl", "hyper-v", "virtual", "vpn", "dummy",
	}
	for _, marker := range markers {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}
