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

package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/policy/api"
	log "github.com/sirupsen/logrus"
)

type rule struct {
	api.Rule
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

func (r *rule) validate() error {
	if r == nil || r.EndpointSelector.LabelSelector == nil {
		return fmt.Errorf("nil rule")
	}

	if len(r.EndpointSelector.MatchLabels) == 0 &&
		len(r.EndpointSelector.MatchExpressions) == 0 {
		return fmt.Errorf("empty EndpointSelector")
	}

	return nil
}


//TODO this is across all the ports of the entire cluster..
func mergeL4Port(ctx *SearchContext, r api.PortRule, p api.PortProtocol, dir string, proto string, resMap L4PolicyMap) int {
	fmt := p.Port + "/" + proto
	log.Debug("MK in mergeL4Port with api.PortRule: ",r," api.PortProtocol:", p," dir:", dir, " proto:",proto, " L4PolicyMap:",resMap )

	v, ok := resMap[fmt]
	if !ok {
		resMap[fmt] = CreateL4Filter(r, p, dir, proto)
		return 1
	}
	l4Filter := CreateL4Filter(r, p, dir, proto)
	if l4Filter.L7Parser != "" {
		log.Debug("MK in mergeL4Port l4Filter.L7Parser:",l4Filter.L7Parser)
		v.L7Parser = l4Filter.L7Parser
	}
	if l4Filter.L7RedirectPort != 0 { //TODO >>>>>>>>>>> here here,,, errflag = true if port = 80 , http and then port = 80 = kafka by 2 different yamls..
		v.L7RedirectPort = l4Filter.L7RedirectPort
	}
	v.L7Rules = append(v.L7Rules, l4Filter.L7Rules...)
	resMap[fmt] = v
	return 1
}

func mergeL4(ctx *SearchContext, dir string, portRules []api.PortRule, resMap L4PolicyMap) int {
	found := 0
	log.Debug("MK in mergeL4 with portRules: ",portRules, " resmap:",resMap, " dir:",dir)

	for _, r := range portRules {
		ctx.PolicyTrace("  Allows %s port %v\n", dir, r.Ports)

		if r.RedirectPort != 0 {
			ctx.PolicyTrace("    Redirect-To: %d\n", r.RedirectPort)
		}

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("      %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != "" {
				log.Debug("MK in mergeL4 loopport p.Protocol != empty")
				found += mergeL4Port(ctx, r, p, dir, p.Protocol, resMap)
			} else {
				log.Debug("MK in mergeL4 tcp/udp p.Protocol = empty")
				found += mergeL4Port(ctx, r, p, dir, "tcp", resMap)
				found += mergeL4Port(ctx, r, p, dir, "udp", resMap)
			}
		}
	}

	return found
}

func (r *rule) resolveL4Policy(ctx *SearchContext, state *traceState, result *L4Policy) *L4Policy {
	log.Debug("MK in resolveL4Policy state:",state, " result:",result)
	if !r.EndpointSelector.Matches(ctx.To) {
		ctx.PolicyTraceVerbose("  Rule %d %s: no match\n", state.ruleID, r)
		return nil
	}

	state.selectedRules++
	ctx.PolicyTrace("* Rule %d %s: match\n", state.ruleID, r)
	found := 0

	if !ctx.EgressL4Only {
		log.Debug("MK in resolveL4Policy ingress true")
		for _, r := range r.Ingress {
			found += mergeL4(ctx, "Ingress", r.ToPorts, result.Ingress)
		}
	}

	if !ctx.IngressL4Only {
		log.Debug("MK in resolveL4Policy egress true")
		for _, r := range r.Egress {
			found += mergeL4(ctx, "Egress", r.ToPorts, result.Egress)
		}
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L4 rules\n")
	return nil
}

func mergeL3(ctx *SearchContext, dir string, ipRules []api.CIDR, resMap *L3PolicyMap) int {
	found := 0

	for _, r := range ipRules {
		strCIDR := string(r)
		ctx.PolicyTrace("  Allows %s IP %s\n", dir, strCIDR)

		found += resMap.Insert(strCIDR)
	}

	return found
}

func (r *rule) resolveL3Policy(ctx *SearchContext, state *traceState, result *L3Policy) *L3Policy {
	if !r.EndpointSelector.Matches(ctx.To) {
		ctx.PolicyTraceVerbose("  Rule %d %s: no match\n", state.ruleID, r)
		return nil
	}

	state.selectedRules++
	ctx.PolicyTrace("* Rule %d %s: match\n", state.ruleID, r)
	found := 0

	for _, r := range r.Ingress {
		found += mergeL3(ctx, "Ingress", r.FromCIDR, &result.Ingress)
	}
	for _, r := range r.Egress {
		found += mergeL3(ctx, "Egress", r.ToCIDR, &result.Egress)
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L3 rules\n")
	return nil
}

func (r *rule) canReach(ctx *SearchContext, state *traceState) api.Decision {
	if !r.EndpointSelector.Matches(ctx.To) {
		ctx.PolicyTraceVerbose("  Rule %d %s: no match for %+v\n", state.ruleID, r, ctx.To)
		return api.Undecided
	}

	state.selectedRules++
	ctx.PolicyTrace("* Rule %d %s: match\n", state.ruleID, r)

	for _, r := range r.Ingress {
		for _, sel := range r.FromRequires {
			ctx.PolicyTrace("    Requires from labels %+v", sel)
			if !sel.Matches(ctx.From) {
				ctx.PolicyTrace("-     Labels %v not found\n", ctx.From)
				return api.Denied
			}
			ctx.PolicyTrace("+     Found all required labels\n")
		}
	}

	// separate loop is needed as failure to meet FromRequires always takes
	// precedence over FromEndpoints
	for _, r := range r.Ingress {
		for _, sel := range r.FromEndpoints {
			ctx.PolicyTrace("    Allows from labels %+v", sel)
			if sel.Matches(ctx.From) {
				ctx.PolicyTrace("+     Found all required labels\n")
				return api.Allowed
			}

			ctx.PolicyTrace("      Labels %v not found\n", ctx.From)
		}
	}

	return api.Undecided
}
