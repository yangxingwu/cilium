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

package tunnel

import (
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"

	"github.com/sirupsen/logrus"
)

const (
	mapName = "tunnel_endpoint_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536

	fieldEndpoint = "endpoint"
	fieldPrefix   = "prefix"
)

var (
	// TunnelMap represents the BPF map for tunnels
	TunnelMap = bpf.NewMap(mapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tunnelEndpoint{})),
		int(unsafe.Sizeof(tunnelEndpoint{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := tunnelEndpoint{}, tunnelEndpoint{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}

			return k, v, nil
		})

	log = logging.DefaultLogger
)

func init() {
	TunnelMap.NonPersistent = true
	bpf.OpenAfterMount(TunnelMap)
}

type tunnelEndpoint struct {
	bpf.EndpointKey
}

func newTunnelEndpoint(ip net.IP) tunnelEndpoint {
	return tunnelEndpoint{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

func (v tunnelEndpoint) NewValue() bpf.MapValue { return &tunnelEndpoint{} }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func SetTunnelEndpoint(prefix net.IP, endpoint net.IP) error {
	key, val := newTunnelEndpoint(prefix), newTunnelEndpoint(endpoint)
	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
	}).Debug("bpf: Updating tunnel endpoint in BPF map")
	return TunnelMap.Update(key, val)
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func DeleteTunnelEndpoint(prefix net.IP) error {
	log.WithField(fieldPrefix, prefix).Debug("bpf: Deleting tunnel endpoint in BPF map")
	return TunnelMap.Delete(newTunnelEndpoint(prefix))
}
