// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/tunnel"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var log = logging.DefaultLogger

const (
	defaultClusterName = "default"

	noWarningOnError = false
	warningOnError   = true
)

type clusterConfiguation struct {
	lock.RWMutex

	name                  string
	nodes                 map[Identity]*Node
	ciliumHostInitialized bool
	usePerNodeRoutes      bool
	auxPrefixes           []*net.IPNet
}

var clusterConf = newClusterConfiguration()

func newClusterConfiguration() clusterConfiguation {
	return clusterConfiguation{
		name:        defaultClusterName,
		nodes:       map[Identity]*Node{},
		auxPrefixes: []*net.IPNet{},
	}
}

func (cc *clusterConfiguation) getNode(ni Identity) *Node {
	cc.RLock()
	n := cc.nodes[ni]
	cc.RUnlock()
	return n
}

func (cc *clusterConfiguation) addAuxPrefix(prefix *net.IPNet) {
	cc.Lock()
	cc.auxPrefixes = append(cc.auxPrefixes, prefix)
	cc.Unlock()
}

// GetNode returns the node with the given identity, if exists, from the nodes
// map.
func GetNode(ni Identity) *Node {
	return clusterConf.getNode(ni)
}

func deleteTunnelEntry(ip *net.IPNet, warnOnError bool) {
	err := tunnel.DeleteTunnelEndpoint(ip.IP)
	if err != nil && warnOnError {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr: ip,
		}).Warning("Unable to delete tunnel endpoint in BPF map")
	}
}

func (n *Node) deleteTunnelEntries(warnOnError bool) {
	n.getLogger().WithFields(logrus.Fields{
		logfields.IPAddr:   n.GetNodeIP(false),
		logfields.V4Prefix: n.IPv4AllocCIDR,
		logfields.V6Prefix: n.IPv6AllocCIDR,
	}).Debug("Deleting tunnel entries of node")

	if n.IPv4AllocCIDR != nil {
		deleteTunnelEntry(n.IPv4AllocCIDR, warnOnError)
	}

	if n.IPv6AllocCIDR != nil {
		deleteTunnelEntry(n.IPv6AllocCIDR, warnOnError)
	}
}

func ipFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}

	return netlink.FAMILY_V4
}

// findRoute finds a particular route as specified by the filter which points
// to the specified device. The filter route can have the following fields set:
//  - Dst
//  - LinkIndex
//  - Scope
//  - Gw
func findRoute(link netlink.Link, route *netlink.Route) *netlink.Route {
	routes, err := netlink.RouteList(link, ipFamily(route.Dst.IP))
	if err != nil {
		return nil
	}

	for _, r := range routes {
		if r.Dst != nil && route.Dst == nil {
			continue
		}

		if route.Dst != nil && r.Dst == nil {
			continue
		}

		aMaskLen, aMaskBits := r.Dst.Mask.Size()
		bMaskLen, bMaskBits := route.Dst.Mask.Size()
		if r.LinkIndex == route.LinkIndex && r.Scope == route.Scope &&
			aMaskLen == bMaskLen && aMaskBits == bMaskBits &&
			r.Dst.IP.Equal(route.Dst.IP) && r.Gw.Equal(route.Gw) {
			return &r
		}
	}

	return nil
}

// replaceNodeRoute verifies that the L2 route for the router IP which is used
// as nexthop for all node routes is properly installed. If unavailable or
// incorrect, it will be replaced with the proper L2 route.
func replaceNexthopRoute(link netlink.Link, routerNet *net.IPNet) error {
	// This is the L2 route which makes the Cilium router IP available behind
	// the "cilium_host" interface. All other routes will use this router IP
	// as nexthop.
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       routerNet,
		Scope:     netlink.SCOPE_LINK,
	}

	if findRoute(link, route) == nil {
		scopedLog := log.WithField(logfields.Route, route)

		if err := netlink.RouteReplace(route); err != nil {
			scopedLog.WithError(err).Error("Unable to add L2 nexthop route")
			return fmt.Errorf("unable to add L2 nexthop route")
		}

		scopedLog.Info("Added L2 nexthop route")
	}

	return nil
}

// replaceNodeRoute verifies whether the specified node CIDR is properly
// covered by a route installed in the host's routing table. If unavailable,
// the route is installed on the host.
func replaceNodeRoute(ip *net.IPNet) {
	if ip == nil {
		return
	}

	link, err := netlink.LinkByName(HostDevice)
	if err != nil {
		log.WithError(err).WithField(logfields.Interface, HostDevice).Error("Unable to lookup interface")
		return
	}

	var routerNet *net.IPNet
	var via, local net.IP
	if ip.IP.To4() != nil {
		via = GetInternalIPv4()
		routerNet = &net.IPNet{IP: via, Mask: net.CIDRMask(32, 32)}
		local = GetInternalIPv4()
	} else {
		via = GetIPv6Router()
		routerNet = &net.IPNet{IP: via, Mask: net.CIDRMask(128, 128)}
		local = GetIPv6()
	}

	if err := replaceNexthopRoute(link, routerNet); err != nil {
		log.WithError(err).Error("Unable to add nexthop route")
	}

	route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: ip, Gw: via, Src: local}
	scopedLog := log.WithField(logfields.Route, route)

	if err := netlink.RouteReplace(&route); err != nil {
		scopedLog.WithError(err).Error("Unable to add node route")
	} else {
		scopedLog.Info("Installed node route")
	}
}

func (cc *clusterConfiguation) updateNodeRoutes() {
	if !cc.ciliumHostInitialized {
		log.Debug("Deferring node routes installation, host device not present yet")
		return
	}

	// We have the option to use per node routes if a control plane is in
	// place which gives us a list of all nodes and their node CIDRs. This
	// allows to share a CIDR with legacy endpoints outside of the cluster
	// but requires individual routes to be installed which creates an
	// overhead with many nodes.
	if cc.usePerNodeRoutes {
		for _, n := range cc.nodes {
			replaceNodeRoute(n.IPv4AllocCIDR)
			replaceNodeRoute(n.IPv6AllocCIDR)
		}
	} else {
		replaceNodeRoute(GetIPv4AllocRange())
		replaceNodeRoute(GetIPv6AllocRange())
	}

	for _, prefix := range cc.auxPrefixes {
		replaceNodeRoute(prefix)
	}
}

func (cc *clusterConfiguation) installHostRoutes() {
	cc.Lock()
	cc.ciliumHostInitialized = true
	cc.updateNodeRoutes()
	cc.Unlock()
}

// InstallHostRoutes installs all required routes to make the following IP
// spaces available from the local host:
//  - node CIDR of local and remote nodes
//  - service CIDR range
//
// This may only be called after the cilium_host interface has been initialized
// for the first time
func InstallHostRoutes() {
	clusterConf.installHostRoutes()
}

// AddAuxPrefix adds additional prefixes for which routes should be installed
// that point to the Cilium network. This function does not directly install
// the route but schedules it for addition by InstallHostRoutes
func AddAuxPrefix(prefix *net.IPNet) {
	clusterConf.addAuxPrefix(prefix)
}

// EnablePerNodeRoutes enables use of per node routes. This function must be called
// at init time before any routes are installed.
func EnablePerNodeRoutes() {
	clusterConf.Lock()
	clusterConf.usePerNodeRoutes = true
	clusterConf.Unlock()
}

func updateTunnelEntry(n *Node, ip *net.IPNet) {
	if ip == nil {
		return
	}

	if err := tunnel.SetTunnelEndpoint(ip.IP, n.GetNodeIP(false)); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr: ip,
		}).Error("bpf: Unable to update in tunnel endpoint map")
	}
}

func (n *Node) updateTunnelEntries() {
	n.getLogger().WithFields(logrus.Fields{
		logfields.IPAddr:   n.GetNodeIP(false),
		logfields.V4Prefix: n.IPv4AllocCIDR,
		logfields.V6Prefix: n.IPv6AllocCIDR,
	}).Debug("Updating tunnel entries of node")

	updateTunnelEntry(n, n.IPv4AllocCIDR)
	updateTunnelEntry(n, n.IPv6AllocCIDR)
}

// Update must be called when the node information was updated
//
// Updates the new node in the nodes' map with the given identity.  This also
// updates the local routing tables and tunnel lookup maps according to the
// node's preferred way of being reached.
func (n *Node) Update() {
	clusterConf.Lock()
	defer clusterConf.Unlock()

	ni := n.getIdentity()
	oldNode, oldNodeExists := clusterConf.nodes[ni]

	clusterConf.nodes[ni] = n
	clusterConf.updateNodeRoutes()

	if n.Routing == nil {
		// Remove all routing information to the node when the node
		// removes its reachability information
		if oldNode != nil && oldNode.Routing != nil {
			oldNode.deleteTunnelEntries(noWarningOnError)
			oldNode.deleteIPRoute(noWarningOnError)
		}

		// No routing configuration provided, all code below depends on
		return
	}

	if n.Routing.Encapsulation != EncapsulationDisabled {
		if oldNodeExists {
			oldNode.deleteTunnelEntries(warningOnError)
		}

		// GH-XXX
		// For now, the datapath is only capable of reaching other
		// nodes using encapsulation protocols that match the local
		// configuration.
		localMode := GetLocalNode().Routing.Encapsulation
		if n.Routing.Encapsulation != localMode {
			n.getLogger().Warningf("Remote node is requesting to be reached via %s, local node is using %s",
				n.Routing.Encapsulation, localMode)
			return
		}

		n.updateTunnelEntries()
	} else {
		// if the node was configured before and encapsulation was
		// enabled, remove the configuration used
		if oldNode != nil && oldNode.Routing != nil &&
			oldNode.Routing.Encapsulation != EncapsulationDisabled {
			oldNode.deleteTunnelEntries(warningOnError)
		}

		// ensure that no tunnel entry exists for the node. This should
		// typically be a no-op
		n.deleteTunnelEntries(noWarningOnError)
	}

	if n.Routing.DirectRoute {
		updateIPRoute(oldNode, n)
	} else {
		if oldNode != nil && oldNode.Routing != nil && oldNode.Routing.DirectRoute {
			oldNode.deleteIPRoute(warningOnError)
		}

		n.deleteIPRoute(noWarningOnError)
	}
}

// DeleteNode remove the node from the nodes' maps and / or the L3 routes to
// reach that node.
func DeleteNode(ni Identity) {
	clusterConf.Lock()
	defer clusterConf.Unlock()

	if n, ok := clusterConf.nodes[ni]; ok {
		n.deleteTunnelEntries(noWarningOnError)
		n.deleteIPRoute(noWarningOnError)
		delete(clusterConf.nodes, ni)
		clusterConf.updateNodeRoutes()
	}
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func GetNodes() map[Identity]Node {
	clusterConf.RLock()
	defer clusterConf.RUnlock()

	nodes := make(map[Identity]Node)
	for id, node := range clusterConf.nodes {
		nodes[id] = *node
	}

	return nodes
}

// updateIPRoute updates the IP routing entry for the given node n via the
// network interface that as ownAddr.
func updateIPRoute(oldNode, n *Node) {
	if n.IPv6AllocCIDR == nil {
		return
	}
	ownAddr := GetIPv6()
	nodeIPv6 := n.GetNodeIP(true)
	scopedLog := n.getLogger().WithField(logfields.V6Prefix, n.IPv6AllocCIDR)
	scopedLog.WithField(logfields.IPAddr, nodeIPv6).Debug("iproute: Setting endpoint v6 route for prefix via IP")

	nl, err := firstLinkWithv6(ownAddr)
	if err != nil {
		scopedLog.WithError(err).WithField(logfields.IPAddr, ownAddr).Error("iproute: Unable to get v6 interface with IP")
		return
	}
	dev := nl.Attrs().Name
	if dev == "" {
		scopedLog.WithField(logfields.IPAddr, ownAddr).Error("iproute: Unable to get v6 interface for address: empty interface name")
		return
	}

	if oldNode != nil {
		oldNodeIPv6 := oldNode.GetNodeIP(true)
		if oldNode.IPv6AllocCIDR.String() != n.IPv6AllocCIDR.String() ||
			!oldNodeIPv6.Equal(nodeIPv6) ||
			oldNode.dev != n.dev {
			// If any of the routing components changed, then remove the old entries
			oldNode.deleteIPRoute(warningOnError)
		}
	} else {
		n.dev = dev
	}

	// Always re add
	err = routeAdd(nodeIPv6.String(), n.IPv6AllocCIDR.String(), dev)
	if err != nil {
		n.getLogger().WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr:   nodeIPv6,
			logfields.V6Prefix: n.IPv6AllocCIDR,
			"device":           dev,
		}).Warn("Cannot re-add route")
		return
	}
}

// deleteIPRoute deletes the routing entries previously created for the given
// node.
func (n *Node) deleteIPRoute(warnOnError bool) {
	oldNodeIPv6 := n.GetNodeIP(true)

	err := routeDel(oldNodeIPv6.String(), n.IPv6AllocCIDR.String(), n.dev)
	if err != nil && warnOnError {
		n.getLogger().WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr:   oldNodeIPv6,
			logfields.V6Prefix: n.IPv6AllocCIDR,
			"device":           n.dev,
		}).Warn("Cannot delete route")
	}
}

// firstLinkWithv6 returns the first network interface that contains the given
// IPv6 address.
func firstLinkWithv6(ip net.IP) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		addrs, _ := netlink.AddrList(l, netlink.FAMILY_V6)
		for _, a := range addrs {
			if ip.Equal(a.IP) {
				return l, nil
			}
		}
	}

	return nil, fmt.Errorf("No address found")
}

func routeAdd(dstNode, podCIDR, dev string) error {
	prog := "ip"

	// for example: ip -6 r a fd00::b dev eth0
	// TODO: don't add direct route if a subnet of that IP is already present
	// in the routing table
	args := []string{"-6", "route", "add", dstNode, "dev", dev}
	out, err := exec.Command(prog, args...).CombinedOutput()
	// Ignore file exists in case the route already exists
	if err != nil && !bytes.Contains(out, []byte("File exists")) {
		return fmt.Errorf("unable to add routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}

	// now we can add the pods cidr route via the other's node IP
	// for example: ip -6 r a f00d::ac1f:32:0:0/96 via fd00::b
	args = []string{"-6", "route", "add", podCIDR, "via", dstNode}
	out, err = exec.Command(prog, args...).CombinedOutput()
	// Ignore file exists in case the route already exists
	if err != nil && !bytes.Contains(out, []byte("File exists")) {
		return fmt.Errorf("unable to add routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}
	return nil
}

func routeDel(dstNode, podCIDR, dev string) error {
	prog := "ip"

	args := []string{"-6", "route", "del", podCIDR, "via", dstNode}
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to clean up old routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}

	args = []string{"-6", "route", "del", dstNode, "dev", dev}
	out, err = exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to clean up old routing entry, command %s %s failed: %s: %s", prog,
			strings.Join(args, " "), err, out)
	}
	return nil
}
