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

	"encoding/binary"
	log "github.com/sirupsen/logrus"
	"strings"
	"sync"
)

/*
 RequestMessage => ApiKey ApiVersion CorrelationId ClientId RequestMessage
  ApiKey => int16
  ApiVersion => int16
  CorrelationId => int32
  ClientId => string
  RequestMessage => MetadataRequest | ProduceRequest | FetchRequest | OffsetRequest | OffsetCommitRequest | OffsetFetchRequest
*/

type KafKaRequestHeader struct {
	// Size of the request
	Size int32
	// ID of the API (e.g. produce, fetch, metadata)
	APIKey int16
	// Version of the API to use
	APIVersion int16
	// User defined ID to correlate requests between server and client
	CorrelationID int32
	// Size of the Client ID
	ClientID string
}

/*
	Response => CorrelationId ResponseMessage
	CorrelationId => int32
	ResponseMessage => MetadataResponse | ProduceResponse | FetchResponse | OffsetResponse | OffsetCommitResponse | OffsetFetchResponse
*/

type KafKaResponseHeader struct {
	// Size of the response
	Size int32
	// User defined ID to correlate requests/responses between server and client
	CorrelationID int32
	//Body          ResponseBody
}

/*
v0, v1 (supported in 0.9.0 or later) and v2 (supported in 0.10.0 or later)
ProduceRequest => RequiredAcks Timeout [TopicName [Partition MessageSetSize MessageSet]]
  RequiredAcks => int16
  Timeout => int32
  Partition => int32
  MessageSetSize => int32
*/
type Data struct {
	Partition int32
	RecordSet []byte
}

type TopicData struct {
	Topic string
	Data  []*Data
}

type ProduceRequest struct {
	Acks      int16
	Timeout   int32
	TopicData []*TopicData
}

/*
 FetchRequest => ReplicaId MaxWaitTime MinBytes [TopicName [Partition FetchOffset MaxBytes]]
  ReplicaId => int32
  MaxWaitTime => int32
  MinBytes => int32
  TopicName => string
  Partition => int32
  FetchOffset => int64
  MaxBytes => int32
*/

// KafkaAPIKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var KafkaAPIKeyMap = map[string]int{
	"produce":              0,  /* Produce */
	"fetch":                1,  /* Fetch */
	"offsets":              2,  /* Offsets */
	"metadata":             3,  /* Metadata */
	"leaderandisr":         4,  /* LeaderAndIsr */
	"stopreplica":          5,  /* StopReplica */
	"updatemetadata":       6,  /* UpdateMetadata */
	"controlledshutdown":   7,  /* ControlledShutdown */
	"offsetcommit":         8,  /* OffsetCommit */
	"offsetfetch":          9,  /* OffsetFetch */
	"findcoordinator":      10, /* FindCoordinator */
	"joingroup":            11, /* JoinGroup */
	"heartbeat":            12, /* Heartbeat */
	"leavegroup":           13, /* LeaveGroup */
	"syncgroup":            14, /* SyncGroup */
	"describegroups":       15, /* DescribeGroups */
	"listgroups":           16, /* ListGroups */
	"saslhandshake":        17, /* SaslHandshake */
	"apiversions":          18, /* ApiVersions */
	"createtopics":         19, /* CreateTopics */
	"deletetopics":         20, /* DeleteTopics */
	"deleterecords":        21, /* DeleteRecords */
	"initproducerid":       22, /* InitProducerId */
	"offsetforleaderepoch": 23, /* OffsetForLeaderEpoch */
	"addpartitionstotxn":   24, /* AddPartitionsToTxn */
	"addoffsetstotxn":      25, /* AddOffsetsToTxn */
	"endtxn":               26, /* EndTxn */
	"writetxnmarkers":      27, /* WriteTxnMarkers */
	"txnoffsetcommit":      28, /* TxnOffsetCommit */
	"describeacls":         29, /* DescribeAcls */
	"createacls":           30, /* CreateAcls */
	"deleteacls":           31, /* DeleteAcls */
	"describeconfigs":      32, /* DescribeConfigs */
	"alterconfigs":         33, /* AlterConfigs */
}

type FetchPartition struct {
	Partition   int32
	FetchOffset int64
	MaxBytes    int32
}

type FetchTopic struct {
	Topic      string
	Partitions []*FetchPartition
}

type FetchRequest struct {
	ReplicaID   int32
	MaxWaitTime int32
	MinBytes    int32
	Topics      []*FetchTopic
}

func translateKafkaPolicyRules(l4 *policy.L4Filter) ([]string, error) {
	var l7rules []string

	log.Debug("MK in translateKafkaPolicyRules ")
	for _, k := range l4.L7Rules.Kafka {
		var r string

		if k.APIVersion != "" {
			r = "APIVersion(\"" + k.APIVersion + "\")"
		}

		if k.APIKey != "" {
			if r != "" {
				r += " && "
			}
			r += "APIKey(\"" + string(KafkaAPIKeyMap[strings.ToLower(k.APIKey)]) + "\")"
		}

		if k.Topic != "" {
			if r != "" {
				r += " && "
			}
			r += "Topic(\"" + k.Topic + "\")"
		}
		log.Debug("MK in translateKafkaPolicyRules loop rule:", r)
		l7rules = append(l7rules, r)
	}

	return l7rules, nil
}

type kafkaRouter struct {
	mutex  *sync.RWMutex
	routes map[string]int32
}

// Router implements kafka request routing and operations.
type KafkaRouter interface {
	// GetRoute returns a route by a given expression,
	// returns nil if expression is not found
	GetRoute(string) int32

	// AddRoute adds a route to match by expression,
	// returns error if the expression already defined,
	// or route expression is incorrect
	AddRoute(string) error

	// RemoveRoute removes a route for a given expression
	RemoveRoute(string) error
}

// New creates a new Router instance
func KafkaRouterNew() KafkaRouter {
	return &kafkaRouter{
		mutex:  &sync.RWMutex{},
		routes: make(map[string]int32),
	}
}

func (e *kafkaRouter) GetRoute(expr string) int32 {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	res, ok := e.routes[expr]
	if ok {
		return res
	}
	return 0
}

func (e *kafkaRouter) AddRoute(expr string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if _, ok := e.routes[expr]; ok {
		log.Debug("Expression already exists :", expr)
		return nil
	}

	e.routes[expr] = 1
	return nil
}

func (e *kafkaRouter) RemoveRoute(expr string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	delete(e.routes, expr)
	return nil
}

// KafkaRedirect implements the Redirect interface for an l7 proxy
type KafkaRedirect struct {
	id         string
	listenPort uint16
	epID       uint64
	source     ProxySource
	ingress    bool
	nodeInfo   accesslog.NodeAddressInfo
	router     KafkaRouter

	mutex lock.RWMutex // protecting the fields below
	rules []string
}

// ToPort returns the redirect port of an KafkaRedirect
func (k *KafkaRedirect) ToPort() uint16 {
	return k.listenPort
}

func (k *KafkaRedirect) updateRules(rules []string) {
	log.Debug("MK in updateRules ")
	for _, v := range k.rules {
		k.router.RemoveRoute(v)
	}

	k.rules = make([]string, len(rules))
	copy(k.rules, rules)

	for _, v := range k.rules {
		k.router.AddRoute(v)
	}
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
		router:     KafkaRouterNew(),
		nodeInfo: accesslog.NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	redir.epID = source.GetID()

	l7rules, err := translateKafkaPolicyRules(l4)
	if err != nil {
		return nil, err
	}
	redir.updateRules(l7rules)

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

/*
type KafKaRequestHeader struct {
	// Size of the request
	Size int32
	// ID of the API (e.g. produce, fetch, metadata)
	APIKey int16
	// Version of the API to use
	APIVersion int16
	// User defined ID to correlate requests between server and client
	CorrelationID int32
	// Size of the Client ID
	ClientID string
}


type TopicData struct {
	Topic string
	Data  []*Data
}

type ProduceRequest struct {
	Acks      int16
	Timeout   int32
	TopicData []*TopicData
}


 FetchRequest => ReplicaId MaxWaitTime MinBytes [TopicName [Partition FetchOffset MaxBytes]]
  ReplicaId => int32
  MaxWaitTime => int32
  MinBytes => int32
  TopicName => string
  Partition => int32
  FetchOffset => int64
  MaxBytes => int32


type FetchPartition struct {
	Partition   int32
	FetchOffset int64
	MaxBytes    int32
}

type FetchTopic struct {
	Topic      string
	Partitions []*FetchPartition
}

type FetchRequest struct {
	ReplicaID   int32
	MaxWaitTime int32
	MinBytes    int32
	Topics      []*FetchTopic
}

*/
func filterIngress(bb *[]byte, redir *KafkaRedirect) {
	// Parse size
	b := *bb
	size := binary.BigEndian.Uint32(b)
	log.Debug("filterIngress size:", size)
	apiKey := binary.BigEndian.Uint16(b[4:])
	log.Debug("filterIngress apiKey:", apiKey)

	apiVersion := binary.BigEndian.Uint16(b[6:])
	log.Debug("filterIngress apiVersion:", apiVersion)
	correlationID := binary.BigEndian.Uint16(b[8:])
	log.Debug("filterIngress correlationID:", correlationID)
	clientID := string(b[12:])
	//clientID := binary.BigEndian.String(b[12:])

	topic := ""
	if apiKey == 1 || apiKey == 2 {
		//producer / fetch request
		if apiKey == 1 {
			topic = string((b[(12 + len(clientID) + 6):]))
		} else {
			topic = string((b[(12 + len(clientID) + 12):]))
		}
		log.Debug("filterIngress topic:", topic)
	}

}

func (k *KafkaRedirect) handleConnection(rxConn net.Conn) {
	addr := rxConn.RemoteAddr()
	log.Debug("MK in kafka handleConnection ")
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
	//var pipe = func(src, dst net.Conn, filter func(b *[]byte, kredir *KafkaRedirect)) {
	var pipe = func(src, dst net.Conn, filter func(b *[]byte, kredir *KafkaRedirect)) {
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
				filter(&b, k)
				//filter(b, k)
			}

			n, err = dst.Write(b)
			if err != nil {
				return
			}
		}
	}

	go pipe(rxConn, txConn, filterIngress) // request forwarding
	go pipe(txConn, rxConn, nil)           // response from remote
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *KafkaRedirect) UpdateRules(l4 *policy.L4Filter) error {
	l7rules, err := translateKafkaPolicyRules(l4)
	log.Debug("MK in UpdateRules err from translateKafkaPolicyRules:", err)
	if err == nil {
		k.mutex.Lock()
		k.updateRules(l7rules)
		k.mutex.Unlock()
	}
	return err
}

// Close the redirect.
func (k *KafkaRedirect) Close() {
	// FIXME
}
