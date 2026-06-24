// Package intent correlates post-DNAT flow snapshots back to the pre-DNAT
// destination — the ClusterIP the client originally dialed — recovering
// Kubernetes "service intent" with no BPF or kernel change.
//
// The agent's flow_aggregates poll path is keyed on the post-DNAT 5-tuple and
// carries no pre-DNAT address. But the sock_ops establish/close ring-buffer
// events DO carry original_dst, identified by the same 5-tuple+pid. The agent
// populates this cache from establish events and joins it against poll
// snapshots, so the service-dependency graph can attribute traffic to the
// dialed service rather than the post-DNAT backend pod it happened to land on.
package intent

import "sync"

// Key identifies a connection by the same fields the BPF flow_aggregates key
// uses, so an establish event and a poll snapshot for one connection collide.
type Key struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	PID       uint32
	Protocol  uint8
	Direction uint8
}

// Dst is the pre-DNAT (original) destination recovered for a connection.
type Dst struct {
	IP   uint32
	Port uint16
}

// DefaultMax is the per-generation entry cap when New is called with max <= 0.
// The cache holds at most 2×max entries; 256K mirrors the BPF connections map.
const DefaultMax = 1 << 18

// Cache is a bounded, concurrency-safe map from connection identity to its
// pre-DNAT destination. Entries are added on connection establish and removed
// on close. To stay bounded even when close events are missed, it keeps two
// generations: when the current generation fills, it is demoted to "previous"
// and a fresh one starts; the previous generation is dropped on the next fill.
// Total size is therefore at most 2×max — no tombstones, no scans, all O(1).
type Cache struct {
	mu   sync.RWMutex
	max  int
	cur  map[Key]Dst
	prev map[Key]Dst
}

// New returns a cache holding at most 2×max entries. max <= 0 uses DefaultMax.
func New(max int) *Cache {
	if max <= 0 {
		max = DefaultMax
	}
	return &Cache{
		max:  max,
		cur:  make(map[Key]Dst),
		prev: map[Key]Dst{},
	}
}

// Put records the pre-DNAT destination for a connection.
func (c *Cache) Put(k Key, d Dst) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cur) >= c.max {
		c.prev = c.cur
		c.cur = make(map[Key]Dst, c.max)
	}
	c.cur[k] = d
	delete(c.prev, k) // keep a key in one generation only
}

// Get returns the pre-DNAT destination for a connection, if known.
func (c *Cache) Get(k Key) (Dst, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if d, ok := c.cur[k]; ok {
		return d, true
	}
	d, ok := c.prev[k]
	return d, ok
}

// Delete drops a connection's entry (called on close).
func (c *Cache) Delete(k Key) {
	c.mu.Lock()
	delete(c.cur, k)
	delete(c.prev, k)
	c.mu.Unlock()
}

// Len reports the number of live entries across both generations.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cur) + len(c.prev)
}
