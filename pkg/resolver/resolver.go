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

package resolver

import (
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type Repository interface {
	// Takes sanitized rules
	Add(rules ...api.Rule)
	Remove(labels labels.LabelArray)
	Clear()
}

type IdentityPolicyResolver interface {
	ResolveIdentityPolicy(identity identity.NumericIdentity) IdentityPolicy
}

type IdentityCache func() identity.IdentityCache

// Note - need to figure out how CIDR comes into play here.
func ResolveIdentityPolicies(rules []api.Rule, identityCache identity.IdentityCache, identitiesToResolve []identity.NumericIdentity) map[identity.NumericIdentity]IdentityPolicy {
	return nil
}

// Yum, consumers.
type IdentityPolicyConsumer interface {
	UpdateIdentityPolicies(identitiyPolicies map[identity.NumericIdentity]IdentityPolicy)
}

type IdentityPolicy interface {
	NetworkPolicy() *cilium.NetworkPolicy
}
