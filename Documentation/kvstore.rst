Key-Value Store
###############

Layout
======

All data stored by Cilium in the kvstore is stored using common, shared key prefixes:

===================== ====================
Prefix                Description
===================== ====================
``cilium/``           All keys share this common prefix.
``cilium/state/``     State stored by agents, data is automatically recreated on removal or corruption.
``cilium/conf/``      Configuration, agents will read this to retrieve
                      configuration but will never write to these keys.
                      Used to store agent configuration in the kvstore.
===================== ====================


Cluster Nodes
-------------

Every agent will register itself as a node in the kvstore and make the
following information available to other agents:

- Name
- IP addresses of the node
- Health checking IP addreses
- Allocation range of endpoints on the node

===================================================== ====================
Key                                                   Value
===================================================== ====================
``cilium/state/nodes/v1/<cluster name>/<node name>``  node.Node_
===================================================== ====================

.. _node.Node: https://godoc.org/github.com/cilium/cilium/pkg/node#Node

All node keys are attached to a lease owned by the agent of the respective
node.


Leases
======

Most keys inserted into the key-value store are owned by a particular agent
running on a node. All such keys are inserted with a lease which means these
keys have a lifetime attached which is continuously being renewed by the agent
owned the key. When the agent own the keys dies and does not come back up, all
keys owned by the agent will disappear after double the lifetime. This ensures
that the kvstore remains clean even as nodes disappear due to failure.

The lease lifetime is set to 15 minutes.


Debugging
=========

The contents stored in the kvstore can be queued and manipulate using the
``cilium kvstore`` command. For additional details, see the command reference.

Example:

.. code:: bash

        $ cilium kvstore get --recursive cilium/state/nodes/
        cilium/state/nodes/v1/default/runtime1 => {"Name":"runtime1","IPAddresses":[{"AddressType":"InternalIP","IP":"10.0.2.15"}],"IPv4AllocCIDR":{"IP":"10.11.0.0","Mask":"//8AAA=="},"IPv6AllocCIDR":{"IP":"f00d::a0f:0:0:0","Mask":"//////////////////8AAA=="},"IPv4HealthIP":"","IPv6HealthIP":""}
