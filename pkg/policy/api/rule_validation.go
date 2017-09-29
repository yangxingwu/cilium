// Copyright 2016-2017 Authors of Cilium
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

package api

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	maxPorts = 40
)

// Validate validates a policy rule
func (r Rule) Validate() error {
	for _, i := range r.Ingress {
		if err := i.Validate(); err != nil {
			return err
		}
	}

	for _, e := range r.Egress {
		if err := e.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates an ingress policy rule
func (i IngressRule) Validate() error {
	log.Debug("MK in Validate IngressRule")
	for _, p := range i.ToPorts {
		if err := p.Validate(); err != nil {
			log.Debug("MK in Validate IngressRule ToPorts returning err:", err)
			return err
		}
	}
	for _, p := range i.FromCIDR {
		if err := p.Validate(); err != nil {
			log.Debug("MK in Validate IngressRule FromCIDR returning err:", err)
			return err
		}
	}

	return nil
}

// Validate validates an egress policy rule
func (e EgressRule) Validate() error {
	log.Debug("MK in Validate EgressRule Validate")
	for _, p := range e.ToPorts {
		if err := p.Validate(); err != nil {
			log.Debug("MK in Validate EgressRule Validate ToPorts returning err:", err)
			return err
		}
	}
	for _, p := range e.ToCIDR {
		if err := p.Validate(); err != nil {
			log.Debug("MK in Validate EgressRule Validate ToCIDR returning err:", err)
			return err
		}
	}

	return nil
}

// Validate validates a port policy rule
// TODO validate that L7Rules has *either* HTTP or Kafka defined.
func (pr PortRule) Validate() error {
	log.Debug("MK in PortRule Validate with L7RulesKafka:", pr.Rules.Kafka)
	if len(pr.Ports) > maxPorts {
		log.Debug("MK in PortRule Validate error oo many ports, the max is %d", maxPorts)
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	for _, p := range pr.Ports {
		if err := p.Validate(); err != nil {
			log.Debug("MK in PortRule Validate returning err:", err)
			return err
		}
	}

	return nil
}

// Validate validates a port/protocol pair
func (pp PortProtocol) Validate() error {
	if pp.Port == "" {
		return fmt.Errorf("Port must be specified")
	}

	p, err := strconv.ParseUint(pp.Port, 0, 16)
	if err != nil {
		return fmt.Errorf("Unable to parse port: %s", err)
	}

	if p == 0 {
		return fmt.Errorf("Port cannot be 0")
	}

	switch strings.ToLower(pp.Protocol) {
	case "", "any", "tcp", "udp":
	default:
		log.Debug("MK in PortProtocol Validate returning Invalid protocol:", pp.Protocol)
		return fmt.Errorf("Invalid protocol %q, must be { tcp | udp }", pp.Protocol)
	}

	return nil
}

// Validate CIDR
func (cidr CIDR) Validate() error {
	strCIDR := string(cidr)
	if strCIDR == "" {
		return fmt.Errorf("IP must be specified")
	}

	_, ipnet, err := net.ParseCIDR(strCIDR)
	if err == nil {
		// Returns the prefix length as zero if the mask is not continuous.
		ones, _ := ipnet.Mask.Size()
		if ones == 0 {
			return fmt.Errorf("Mask length can not be zero")
		}
	} else {
		// Try to parse as a fully masked IP or an IP subnetwork
		ip := net.ParseIP(strCIDR)
		if ip == nil {
			return fmt.Errorf("Unable to parse CIDR: %s", err)
		}
	}

	return nil
}
