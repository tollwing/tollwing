package agent

// runShutdown tears down the agent's data-path components in dependency
// order. Cross-platform so the ordering contract is unit-testable off-linux;
// Agent.shutdown (agent.go) binds the real components. The order is
// load-bearing:
//
//  1. stopPoller — the poller's deliberate final flush drains the BPF maps
//     and hands the last batch to handlePoll, which ships it to NATS. It
//     must run while the publisher is still open: the previous defer stack
//     in Run closed NATS first, so the final flush published into a drained
//     connection and every node silently lost one poll interval of flow
//     data on each rolling restart. Per P4, measured bytes must reach the
//     bill — they must not evaporate on SIGTERM.
//  2. closePublisher — drain NATS only after the final batch is in.
//  3. closeLoader — detach the eBPF programs last; the final flush above
//     still reads the loader's maps.
//
// Any step may be nil (that component never started).
func runShutdown(stopPoller, closePublisher, closeLoader func()) {
	if stopPoller != nil {
		stopPoller()
	}
	if closePublisher != nil {
		closePublisher()
	}
	if closeLoader != nil {
		closeLoader()
	}
}
