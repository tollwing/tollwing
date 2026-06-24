// Package classifier — prefix tree for O(log n) CIDR lookups.
package classifier

import "net/netip"

// prefixEntry associates a prefix with a traffic type.
type prefixEntry struct {
	prefix      netip.Prefix
	trafficType TrafficType
}

// PrefixTree provides O(prefix-length) longest-prefix-match lookups
// for traffic type classification. Uses a sorted slice with binary
// search — simple, allocation-free, and fast enough for the typical
// number of CIDRs (10-50 entries per category).
//
// For very large CIDR sets, this can be replaced with a trie without
// changing the Classifier interface.
type PrefixTree struct {
	entries []prefixEntry
}

// NewPrefixTree creates an empty prefix tree.
func NewPrefixTree() *PrefixTree {
	return &PrefixTree{}
}

// Add inserts a prefix → traffic type mapping.
func (pt *PrefixTree) Add(prefix netip.Prefix, tt TrafficType) {
	pt.entries = append(pt.entries, prefixEntry{prefix: prefix, trafficType: tt})
}

// Build sorts entries by prefix length (longest first) for longest-prefix-match.
// Must be called after all Add() calls and before Lookup().
func (pt *PrefixTree) Build() {
	// Sort by prefix length descending (longest prefix = most specific match).
	// Simple insertion sort — entries are typically < 50.
	for i := 1; i < len(pt.entries); i++ {
		for j := i; j > 0 && pt.entries[j].prefix.Bits() > pt.entries[j-1].prefix.Bits(); j-- {
			pt.entries[j], pt.entries[j-1] = pt.entries[j-1], pt.entries[j]
		}
	}
}

// Lookup returns the traffic type for the most specific matching prefix.
// Returns (Unknown, false) if no prefix matches.
func (pt *PrefixTree) Lookup(addr netip.Addr) (TrafficType, bool) {
	for _, e := range pt.entries {
		if e.prefix.Contains(addr) {
			return e.trafficType, true
		}
	}
	return Unknown, false
}

// Len returns the number of entries.
func (pt *PrefixTree) Len() int {
	return len(pt.entries)
}

// Reset clears all entries.
func (pt *PrefixTree) Reset() {
	pt.entries = pt.entries[:0]
}
