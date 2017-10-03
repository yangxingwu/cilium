// Copyright 2017 Authors of Cilium
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

package proxy

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	log "github.com/sirupsen/logrus"
)

// KafkaRedirect implements the Redirect interface for an l7 proxy
type KafkaRedirect struct {
	id         string
	listenPort uint16
	epID       uint64
	source     ProxySource
	ingress    bool
	nodeInfo   accesslog.NodeAddressInfo

	mutex lock.RWMutex // protecting the fields below
	rules []string
}

// ToPort returns the redirect port of an OxyRedirect
func (k *KafkaRedirect) ToPort() uint16 {
	return k.listenPort
}

func (k *KafkaRedirect) updateRules(rules []string) {
	// FIXME
}

// createKafkaRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createKafkaRedirect(l4 *policy.L4Filter, id string, source ProxySource, listenPort uint16) (Redirect, error) {
	if l4.L7Parser != policy.ParserTypeKafka {
		return nil, fmt.Errorf("unknown L7 protocol \"%s\"", l4.L7Parser)
	}

	redir := &KafkaRedirect{
		id:         id,
		listenPort: listenPort,
		source:     source,
		ingress:    l4.Ingress,
		nodeInfo: accesslog.NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	redir.epID = source.GetID()

	marker := GetMagicMark(redir.ingress)

	// As ingress proxy, all replies to incoming requests must have the
	// identity of the endpoint we are proxying for
	if redir.ingress {
		marker |= int(source.GetIdentity())
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	listener, err := listenSocket(fmt.Sprintf(":%d", redir.listenPort), marker)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.WithFields(log.Fields{
					"listenPort": redir.listenPort,
				}).WithError(err).Error("Unable to accept connection")
				continue
			}

			go redir.handleConnection(conn)
		}
	}()

	return redir, nil
}

func (k *KafkaRedirect) handleConnection(rxConn net.Conn) {
	addr := rxConn.RemoteAddr()
	if addr == nil {
		log.Warning("RemoteAddr() is nil")
		return
	}

	srcIdentity, dstIPPort, err := lookupNewDest(addr.String(), k.listenPort)
	if err != nil {
		log.WithFields(log.Fields{
			"source": addr.String(),
		}).WithError(err).Error("Unable lookup original destination")
		return
	}

	marker := GetMagicMark(k.ingress) | int(srcIdentity)
	txConn, err := ciliumDialer(marker, addr.Network(), dstIPPort)
	if err != nil {
		log.WithFields(log.Fields{
			"origNetwork": addr.Network(),
			"origDest":    dstIPPort,
		}).WithError(err).Error("Unable dial original destination")
		return
	}

	// pipeDone counts closed pipe
	var pipeDone int32
	var timer *time.Timer

	// write to dst what it reads from src
	var pipe = func(src, dst net.Conn, filter func(b *[]byte)) {
		defer func() {
			// if it is the first pipe to end...
			if v := atomic.AddInt32(&pipeDone, 1); v == 1 {
				// ...wait 'timeout' seconds before closing connections
				timer = time.AfterFunc(time.Minute, func() {
					// test if the other pipe is still alive before closing conn
					if atomic.AddInt32(&pipeDone, 1) == 2 {
						rxConn.Close()
						txConn.Close()
					}
				})
			} else if v == 2 {
				rxConn.Close()
				txConn.Close()
				timer.Stop()
			}
		}()

		buff := make([]byte, 65535)
		for {
			n, err := src.Read(buff)
			if err != nil {
				return
			}
			b := buff[:n]

			if filter != nil {
				filter(&b)
			}

			n, err = dst.Write(b)
			if err != nil {
				return
			}
		}
	}

	go pipe(rxConn, txConn, nil)
	go pipe(txConn, rxConn, nil)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *KafkaRedirect) UpdateRules(l4 *policy.L4Filter) error {
	// FIXME
	return nil
}

// Close the redirect.
func (k *KafkaRedirect) Close() {
	// FIXME
}
