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
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

// Identity represents the node identity of a node.
type Identity struct {
	Name string
}

// String returns the string representation on NodeIdentity.
func (nn Identity) String() string {
	return nn.Name
}

// EncapsulationType is a networking encapsulation type
type EncapsulationType int

const (
	// EncapsulationDisabled indicates to disable encapsulation
	EncapsulationDisabled EncapsulationType = iota

	// EncapsulationVXLAN indicates to use VXLAN encapsulation mode
	EncapsulationVXLAN

	// EncapsulationGeneve indicates to use Geneve encapsulation mode
	EncapsulationGeneve
)

func (et EncapsulationType) String() string {
	switch et {
	case EncapsulationDisabled:
		return "disabled"
	case EncapsulationVXLAN:
		return "vxlan"
	case EncapsulationGeneve:
		return "geneve"
	}

	return "unknown"
}

// RoutingConfiguration is the configuration of the node that defines how to
// reach endpoints running on the node
type RoutingConfiguration struct {
	// Encapsulation defines whether and how the endpoints on the node can
	// be reached using network encapsulation. Encapsulation is always the
	// preferred routing mode unless it is explicitly disabled.
	Encapsulation EncapsulationType

	// DirectRoute indicates that the node's endpoints can be reached via a
	// direct route that uses the node's external IP address as gateway.
	// Enabling this flag does not automatically prefer direct routing,
	// encapsulation must be disabled in order for direct routing to take
	// place.
	DirectRoute bool
}

func (rc RoutingConfiguration) String() string {
	return fmt.Sprintf("encapsulation=%s direct-routing=%t", rc.Encapsulation, rc.DirectRoute)
}

// Node contains the nodes name, the list of addresses to this address
type Node struct {
	// Name is the FQDN (inside the cluster) of the node
	Name string

	// IPAddresses is the list of external and internal addresses
	// associated with the node
	IPAddresses []Address

	// IPv4AllocCIDR if set, is the IPv4 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv4AllocCIDR *net.IPNet

	// IPv6AllocCIDR if set, is the IPv6 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv6AllocCIDR *net.IPNet

	// IPv4HealthIP if not nil, this is the IPv4 address of the
	// cilium-health endpoint located on the node.
	IPv4HealthIP net.IP

	// IPv6HealthIP if not nil, this is the IPv6 address of the
	// cilium-health endpoint located on the node.
	IPv6HealthIP net.IP

	// Routing defines the routing configuration and reachability
	// information how to retrieve endpoints on the node
	Routing *RoutingConfiguration

	// Labels provides a mechanism to attach metadata to nodes
	Labels labels.Labels

	// Private fields
	// These fields are not synchronized via the kvstore

	// cluster membership
	cluster *clusterConfiguation

	// dev contains the device name to where the IPv6 traffic should be send
	dev string
}

// Address is a node address which contains an IP and the address type.
type Address struct {
	AddressType v1.NodeAddressType
	IP          net.IP
}

func (n *Node) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		logfields.NodeName: n.Name,
	})
}

func (n *Node) getNodeIP(ipv6 bool) (net.IP, v1.NodeAddressType) {
	var (
		backupIP net.IP
		ipType   v1.NodeAddressType
	)
	for _, addr := range n.IPAddresses {
		if (ipv6 && addr.IP.To4() != nil) ||
			(!ipv6 && addr.IP.To4() == nil) {
			continue
		}
		switch addr.AddressType {
		// Always prefer a cluster internal IP
		case v1.NodeInternalIP:
			return addr.IP, addr.AddressType
		case v1.NodeExternalIP:
			// Fall back to external Node IP
			// if no internal IP could be found
			backupIP = addr.IP
			ipType = addr.AddressType
		default:
			// As a last resort, if no internal or external
			// IP was found, use any node address available
			if backupIP == nil {
				backupIP = addr.IP
				ipType = addr.AddressType
			}
		}
	}
	return backupIP, ipType
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
func (n *Node) GetNodeIP(ipv6 bool) net.IP {
	result, _ := n.getNodeIP(ipv6)
	return result
}

func (n *Node) getPrimaryAddress(ipv4 bool) *models.NodeAddressing {
	v4, v4Type := n.getNodeIP(false)
	v6, v6Type := n.getNodeIP(true)

	var ipv4AllocStr, ipv6AllocStr string
	if n.IPv4AllocCIDR != nil {
		ipv4AllocStr = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		ipv6AllocStr = n.IPv6AllocCIDR.String()
	}
	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled:     ipv4,
			IP:          v4.String(),
			AllocRange:  ipv4AllocStr,
			AddressType: string(v4Type),
		},
		IPV6: &models.NodeAddressingElement{
			Enabled:     !ipv4,
			IP:          v6.String(),
			AllocRange:  ipv6AllocStr,
			AddressType: string(v6Type),
		},
	}
}

func (n *Node) isPrimaryAddress(addr Address, ipv4 bool) bool {
	return addr.IP.String() == n.GetNodeIP(!ipv4).String()
}

func (n *Node) getSecondaryAddresses(ipv4 bool) []*models.NodeAddressingElement {
	result := []*models.NodeAddressingElement{}

	for _, addr := range n.IPAddresses {
		if !n.isPrimaryAddress(addr, ipv4) {
			result = append(result, &models.NodeAddressingElement{
				IP:          addr.IP.String(),
				AddressType: string(addr.AddressType),
			})
		}
	}

	return result
}

func (n *Node) getHealthAddresses(ipv4 bool) *models.NodeAddressing {
	if n.IPv4HealthIP == nil || n.IPv6HealthIP == nil {
		return nil
	}
	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled: ipv4,
			IP:      n.IPv4HealthIP.String(),
		},
		IPV6: &models.NodeAddressingElement{
			Enabled: !ipv4,
			IP:      n.IPv6HealthIP.String(),
		},
	}
}

// GetModel returns the API model representation of a node.
func (n *Node) GetModel(ipv4 bool) *models.NodeElement {
	return &models.NodeElement{
		Name:                  n.Name,
		PrimaryAddress:        n.getPrimaryAddress(ipv4),
		SecondaryAddresses:    n.getSecondaryAddresses(ipv4),
		HealthEndpointAddress: n.getHealthAddresses(ipv4),
	}
}

func (n *Node) getIdentity() Identity {
	return Identity{Name: n.Name}
}

// Delete removes the nodes from the cluster
func (n *Node) Delete() {
	DeleteNode(n.getIdentity())
}

var localRoutingConfiguration *RoutingConfiguration

// GetLocalNode returns the identity and node spec for the local node
func GetLocalNode() *Node {
	return &Node{
		Name:    nodeName,
		cluster: &clusterConf,
		Routing: localRoutingConfiguration,
		IPAddresses: []Address{
			{
				AddressType: v1.NodeInternalIP,
				IP:          GetExternalIPv4(),
			},
		},
		IPv4AllocCIDR: GetIPv4AllocRange(),
		IPv6AllocCIDR: GetIPv6AllocRange(),
		IPv4HealthIP:  GetIPv4HealthIP(),
		IPv6HealthIP:  GetIPv6HealthIP(),
	}
}

// ConfigureLocalNode configures the local node. This is called on agent
// startup to configure the local node based on the configuration options
// passed to the agent
func ConfigureLocalNode(routing *RoutingConfiguration) {
	localRoutingConfiguration = routing

	log.Infof("Local node routing configuration: %s", routing)
}
