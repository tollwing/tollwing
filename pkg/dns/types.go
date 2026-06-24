// Portable type definitions — visible on all platforms so non-linux
// callers (analyzers, recommenders, tests on macOS) can use the dns
// package types without depending on the linux-only Tracker.
package dns

// QueryCount is one row of a per-domain DNS query counter snapshot.
// Produced by the linux Tracker; consumed by analyzers in dnscost.
type QueryCount struct {
	Domain  string // queried domain (no trailing dot)
	Service string // mapped cloud service name, empty if unmapped
	Count   uint64 // observed query count over the snapshot window
}
