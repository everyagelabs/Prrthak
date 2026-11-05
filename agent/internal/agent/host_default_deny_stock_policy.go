package agent

import (
	"encoding/json"
	"fmt"
)

const nftStockIPv6Dispatch = "filter_INPUT_POLICIES_pre"
const nftStockIPv6Policy = "filter_IN_policy_allow-host-ipv6"

type nftStockPolicyChain struct {
	declared bool
	rules    [][]json.RawMessage
}

type nftStockPolicyContext map[string]*nftStockPolicyChain

var nftStockIPv6Stages = []string{"_pre", "_log", "_deny", "_allow", "_post"}

func newNftStockIPv6Policy() nftStockPolicyContext {
	result := nftStockPolicyContext{
		nftStockIPv6Dispatch: {},
		nftStockIPv6Policy:   {},
	}
	for _, stage := range nftStockIPv6Stages {
		result[nftStockIPv6Policy+stage] = &nftStockPolicyChain{}
	}
	return result
}

func nftStockIPv6Jump(target string) string {
	return fmt.Sprintf(`{"jump":{"target":%q}}`, target)
}

func (context nftStockPolicyContext) proof() (json.RawMessage, bool) {
	for _, chain := range context {
		if !chain.declared {
			return nil, false
		}
	}
	dispatch := context[nftStockIPv6Dispatch].rules
	policy := context[nftStockIPv6Policy].rules
	if len(dispatch) != 1 || !equalNftRule(dispatch[0], nftStockIPv6Jump(nftStockIPv6Policy)) ||
		len(policy) != len(nftStockIPv6Stages) {
		return nil, false
	}
	for i, stage := range nftStockIPv6Stages {
		name := nftStockIPv6Policy + stage
		if !equalNftRule(policy[i], nftStockIPv6Jump(name)) || stage != "_allow" && len(context[name].rules) != 0 {
			return nil, false
		}
	}
	// Every early verdict must be scoped to a stock ICMPv6 type. This
	// proves that new TCP/UDP reaches the zone's own rich-rule pre chain.
	types := []string{"nd-neighbor-advert", "nd-neighbor-solicit", "nd-router-advert", "nd-redirect",
		"mld-listener-done", "mld-listener-query", "mld-listener-report", "mld2-listener-report"}
	rules := context[nftStockIPv6Policy+"_allow"].rules
	if len(rules) != 4 && len(rules) != len(types) {
		return nil, false
	}
	matched := make(map[int]bool, len(rules))
	for _, rule := range rules {
		for i, kind := range types[:len(rules)] {
			match := fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":%q}}`, kind)
			if equalNftRule(rule, match, `{"accept":null}`) {
				matched[i] = true
				break
			}
		}
	}
	if len(matched) != len(rules) {
		return nil, false
	}
	encoded, err := json.Marshal(rules)
	return encoded, err == nil
}
