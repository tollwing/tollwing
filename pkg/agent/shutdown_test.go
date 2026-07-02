package agent

import (
	"testing"
)

// TestRunShutdown_Order locks in the teardown order that fixes the
// lost-final-flush bug: the poller stops (and final-flushes) FIRST, the NATS
// publisher closes second, and the eBPF loader detaches last. The old defer
// stack in Run executed publisher-close before poller-stop, so the final
// flush published into a drained connection and one poll interval of flow
// data vanished per node per rolling restart (P4).
func TestRunShutdown_Order(t *testing.T) {
	tests := []struct {
		name          string
		havePoller    bool
		havePublisher bool
		haveLoader    bool
		want          []string
	}{
		{
			name:       "all components",
			havePoller: true, havePublisher: true, haveLoader: true,
			want: []string{"poller.Stop", "publisher.Close", "loader.Close"},
		},
		{
			name:       "no publisher (NATS disabled)",
			havePoller: true, haveLoader: true,
			want: []string{"poller.Stop", "loader.Close"},
		},
		{
			name:          "no poller (flow_aggregates map missing)",
			havePublisher: true, haveLoader: true,
			want: []string{"publisher.Close", "loader.Close"},
		},
		{
			name: "nothing started",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			record := func(step string) func() {
				return func() { got = append(got, step) }
			}

			var stopPoller, closePublisher, closeLoader func()
			if tt.havePoller {
				stopPoller = record("poller.Stop")
			}
			if tt.havePublisher {
				closePublisher = record("publisher.Close")
			}
			if tt.haveLoader {
				closeLoader = record("loader.Close")
			}

			runShutdown(stopPoller, closePublisher, closeLoader)

			if len(got) != len(tt.want) {
				t.Fatalf("shutdown steps = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("shutdown steps = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestRunShutdown_FinalFlushReachesOpenPublisher simulates the real failure:
// the poller's Stop performs a final flush that publishes its last batch.
// That publish must land while the publisher is still open. Before the fix,
// the publisher was already closed when the flush ran, and the batch was
// warn-and-dropped.
func TestRunShutdown_FinalFlushReachesOpenPublisher(t *testing.T) {
	publisherClosed := false
	flushedWhileOpen := false

	stopPoller := func() {
		// The poller's deliberate final flush → handlePoll → NATS publish.
		if !publisherClosed {
			flushedWhileOpen = true
		}
	}
	closePublisher := func() { publisherClosed = true }

	runShutdown(stopPoller, closePublisher, nil)

	if !publisherClosed {
		t.Fatal("publisher was never closed")
	}
	if !flushedWhileOpen {
		t.Fatal("final flush ran after the NATS publisher closed — the last poll interval of flow data would be dropped")
	}
}
