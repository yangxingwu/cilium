// Copyright 2018 Authors of Cilium
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
	"encoding/json"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"

	"github.com/sirupsen/logrus"
)

const (
	// localNodeRegistrationInterval is the interval in which the local
	// node is re-registered with the kvstore and BPF maps
	localNodeRegistrationInterval = time.Duration(2) * time.Minute

	// timeout to wait for initial list of nodes
	listTimeout = time.Duration(30) * time.Second
)

var (
	// nodesPath is the path to where nodes are stored in the kvstore
	nodesPath = path.Join(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	// controllers contains all controllers required for node management
	controllers controller.Manager
)

var registerOnce sync.Once

// RegisterLocalNode registers the local node in the cluster
func RegisterLocalNode() error {
	n := GetLocalNode()
	n.getLogger().Debug("Registering local node")

	// Perform an initial blocking node registration to ensure that the
	// agent fails when we can't register
	err := n.registerLocalNode()
	if err != nil {
		return fmt.Errorf("unable to register local node: %s", err)
	}

	registerOnce.Do(func() {
		// Following the initial blocking registration, schedule a controller
		// to follow-up and ensure the kvstore entry gets re-added
		go func() {
			time.Sleep(localNodeRegistrationInterval)
			controllers.UpdateController("node-register",
				controller.ControllerParams{
					DoFunc: func() error {
						return n.registerLocalNode()
					},
					RunInterval: localNodeRegistrationInterval,
				},
			)
		}()

		err = startNodeWatcher()
	})

	return err
}

func (n *Node) registerLocalNode() error {
	n.getLogger().Debug("Updating local node registration")

	// Add local node to local list of all cluster nodes
	n.Update()

	// register node entry in kvstore, overwrite any previous value, attach
	// lease to expire entry when agent dies and never comes back up.
	//
	// This does not resolve any conflict regarding node names, it assumes
	// that nodes with identical node names in a cluster represent a new
	// iteration of the same node
	nodeKey := path.Join(nodesPath, n.cluster.name, n.Name)
	nodeValue, err := json.Marshal(n)
	if err != nil {
		return err
	}

	if err := kvstore.Update(nodeKey, nodeValue, true); err != nil {
		return err
	}

	return nil
}

func startNodeWatcher() error {
	listDone := make(chan bool)

	go nodeWatcher(listDone)

	select {
	case <-listDone:
	case <-time.After(listTimeout):
		return fmt.Errorf("Time out while retrieve list of nodes from kvstore")
	}

	return nil
}

func nodeWatcher(listDone chan bool) {
	watcher := kvstore.ListAndWatch("nodes-watcher", nodesPath, 100)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Typ == kvstore.EventTypeListDone {
				log.Debugf("Initial list of nodes received from kvstore")
				close(listDone)
				continue
			}

			var n Node
			if err := json.Unmarshal(event.Value, &n); err != nil {
				log.WithError(err).Warning("Unable to unmarshal node key")
				continue
			}

			n.getLogger().WithFields(logrus.Fields{
				"eventType": event.Typ,
			}).Debugf("Received node update via kvstore %+v", n)

			// ignore notificiation about the local node
			if n.Name == GetLocalNode().Name {
				continue
			}

			switch event.Typ {
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				n.Update()
			case kvstore.EventTypeDelete:
				n.Delete()
			}
		}
	}
}
