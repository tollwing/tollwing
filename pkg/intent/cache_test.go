package intent

import "testing"

func key(srcPort uint16) Key {
	return Key{SrcIP: 0x0a000001, DstIP: 0x0a000002, SrcPort: srcPort, DstPort: 80, PID: 42, Protocol: 6}
}

func TestCachePutGet(t *testing.T) {
	c := New(0)
	k := key(1000)
	if _, ok := c.Get(k); ok {
		t.Fatal("empty cache returned a hit")
	}
	c.Put(k, Dst{IP: 0x0a600001, Port: 443})
	got, ok := c.Get(k)
	if !ok || got.IP != 0x0a600001 || got.Port != 443 {
		t.Fatalf("Get = %+v, %v; want {0x0a600001, 443}, true", got, ok)
	}
}

func TestCacheUpdateDoesNotGrow(t *testing.T) {
	c := New(10)
	k := key(1000)
	c.Put(k, Dst{IP: 1, Port: 1})
	c.Put(k, Dst{IP: 2, Port: 2})
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1 after updating same key", c.Len())
	}
	if got, _ := c.Get(k); got.IP != 2 {
		t.Errorf("Get.IP = %d, want 2 (latest value)", got.IP)
	}
}

func TestCacheDelete(t *testing.T) {
	c := New(0)
	k := key(1000)
	c.Put(k, Dst{IP: 1})
	c.Delete(k)
	if _, ok := c.Get(k); ok {
		t.Error("Get returned a hit after Delete")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0 after Delete", c.Len())
	}
}

// With max=1, each Put past the first rotates generations. A key survives one
// rotation (demoted to prev) then is evicted on the next — bounded, no leak.
func TestCacheGenerationalEviction(t *testing.T) {
	c := New(1)
	k1, k2, k3 := key(1), key(2), key(3)
	c.Put(k1, Dst{IP: 1})
	c.Put(k2, Dst{IP: 2}) // cur={k2}, prev={k1}
	if _, ok := c.Get(k1); !ok {
		t.Error("k1 should survive one rotation (in prev)")
	}
	c.Put(k3, Dst{IP: 3}) // cur={k3}, prev={k2}
	if _, ok := c.Get(k1); ok {
		t.Error("k1 should be evicted after two rotations")
	}
	if _, ok := c.Get(k3); !ok {
		t.Error("k3 (current) should be present")
	}
	if c.Len() > 2 {
		t.Errorf("Len = %d, want <= 2 (two generations of max=1)", c.Len())
	}
}
