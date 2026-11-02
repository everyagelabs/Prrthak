package agent

import (
	"net/netip"
	"sort"
	"strings"
)

type verificationSourceRange struct{ first, last netip.Addr }
type verificationSourceMatcher struct{ ranges []verificationSourceRange }

func verificationBuildMatchers(sources map[string][]string) map[string]*verificationSourceMatcher {
	result := map[string]*verificationSourceMatcher{}
	interned := map[string]*verificationSourceMatcher{}
	for key, values := range sources {
		digest := shaText(strings.Join(values, "\x00"))
		if cached := interned[digest]; cached != nil {
			result[key] = cached
			continue
		}
		ranges := []verificationSourceRange{}
		for _, value := range values {
			if prefix, err := netip.ParsePrefix(value); err == nil {
				prefix = prefix.Masked()
				ranges = append(ranges, verificationSourceRange{prefix.Addr(), verificationPrefixEnd(prefix)})
			}
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].first.Less(ranges[j].first) })
		merged := []verificationSourceRange{}
		for _, interval := range ranges {
			if len(merged) > 0 {
				previous := &merged[len(merged)-1]
				if previous.first.Is4() == interval.first.Is4() && (!previous.last.Less(interval.first) || previous.last.Next() == interval.first) {
					if previous.last.Less(interval.last) {
						previous.last = interval.last
					}
					continue
				}
			}
			merged = append(merged, interval)
		}
		matcher := &verificationSourceMatcher{ranges: merged}
		result[key], interned[digest] = matcher, matcher
	}
	return result
}

func (matcher *verificationSourceMatcher) contains(address netip.Addr) bool {
	if matcher == nil {
		return false
	}
	index := sort.Search(len(matcher.ranges), func(i int) bool { return !matcher.ranges[i].last.Less(address) })
	return index < len(matcher.ranges) && !address.Less(matcher.ranges[index].first)
}
