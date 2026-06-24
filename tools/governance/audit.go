package main

import (
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type principleInfo struct {
	name    string
	lookFor string
}

// principles mirrors CONSTITUTION.md; lookFor distills each principle's
// anti-examples / compliance test into an audit hint.
var principles = map[string]principleInfo{
	"P1":  {"The agent is the product", "agent-side code that adds unbounded state, cross-node correlation, or heavy compute to the DaemonSet instead of the control plane"},
	"P2":  {"Near-zero node overhead is a hard budget", "unbounded maps/caches, missing eviction policy, per-event userspace work on hot paths, absent GOMEMLIMIT/GOGC, hot-path allocation"},
	"P3":  {"Portable, capability-probing data plane", "kernel features used on the required path without a probe, missing minimum-kernel notes, cgo leaking into server/CLI, hooks with no graceful degradation"},
	"P4":  {"Cost numbers are honest and traceable", "dollar figures not traceable to bytes × dated rate, asserted accuracy without reconciliation, hidden/un-bucketed unmeasured spend, attribution that invents or double-counts dollars"},
	"P5":  {"Accurate attribution over convenient approximation", "classification from post-DNAT IPs, unresolved zones defaulted to same_zone instead of Unknown, sidecar/proxy flows counted twice"},
	"P6":  {"One canonical representation; no drift across boundaries", "hardcoded enum string literals (e.g. \"cross_az\") instead of TrafficType.String(); duplicate enum definitions across in-memory/ClickHouse/metrics/API"},
	"P7":  {"Storage is forward-only and additive", "edited or reordered migrations, down-migrations, DROP/RENAME/MODIFY COLUMN, non-idempotent migration SQL"},
	"P8":  {"Automated actions are safe and reversible", "infra-mutating paths without an approval gate or rollback, recommendations that bypass a safety guard, unbounded automated actions"},
	"P9":  {"Stdlib-first; dependencies earn their place", "stdlib \"log\" instead of log/slog; cobra/viper/testify/zap/logrus; new go.mod direct deps without an ADR"},
	"P10": {"Multi-cloud is one abstraction", "`provider ==` branches in classifier/cost, AWS-only assumptions in shared code, provider logic living outside pkg/cloud"},
	"P11": {"Public contracts are versioned and evolve compatibly", "breaking changes to the HTTP API / CRDs / NATS-proto / ClickHouse schema / CLI flags / metric names without a version bump + ADR; a server that breaks older agents; removed fields/endpoints with no deprecation window"},
	"P12": {"Capture only what attribution needs, and protect it", "capturing more than the attribution minimum (payloads, full cmdlines, secrets); sensitive 4-tuples/cmdlines logged at info; no redaction in multi-tenant mode; cross-tenant data leakage; new sensitive capture without an ADR"},
}

// subsystems maps a friendly name to the paths a deep audit should read.
var subsystems = map[string]string{
	"ebpf":         "pkg/ebpf (+ pkg/ebpf/bpf C sources)",
	"classifier":   "pkg/classifier",
	"cost":         "pkg/cost",
	"servicegraph": "pkg/servicegraph (+ pkg/api/servicegraph.go)",
	"storage":      "pkg/storage/clickhouse",
	"dns":          "pkg/dns (+ pkg/dnscost)",
	"intent":       "pkg/intent",
	"agent":        "pkg/agent (+ cmd/tollwing-agent)",
	"api":          "pkg/api (+ cmd/tollwing-server)",
	"remediate":    "pkg/remediate (+ pkg/autoremediate, pkg/admission)",
	"cloud":        "pkg/cloud",
}

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	principle := fs.String("principle", "", "principle ID to audit across the codebase (e.g. P4)")
	subsystem := fs.String("subsystem", "", "subsystem/package to deep-audit (e.g. servicegraph); see -list")
	mode := fs.String("mode", "", "audit mode: A continuous | B subsystem | C principle | D pre-release")
	list := fs.Bool("list", false, "list known principles and subsystems")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *list {
		printAuditList()
		return nil
	}
	if *principle == "" && *subsystem == "" {
		return fmt.Errorf("specify -principle Pn or -subsystem name (or -list); see docs/governance/audit-playbook.md")
	}

	date := time.Now().Format("2006-01-02")

	var scope, lookFor, outName, auditMode string
	switch {
	case *principle != "":
		key := strings.ToUpper(*principle)
		info, ok := principles[key]
		if !ok {
			return fmt.Errorf("unknown principle %q (want P1..P10); run -list", *principle)
		}
		scope = fmt.Sprintf("Principle %s — %s, across the whole codebase (pkg/, cmd/).", key, info.name)
		lookFor = info.lookFor
		outName = fmt.Sprintf("principle-%s-%s.md", strings.ToLower(key), date)
		auditMode = firstNonEmpty(strings.ToUpper(*mode), "C")
	default:
		path, ok := subsystems[*subsystem]
		if !ok {
			path = "pkg/" + *subsystem
		}
		scope = fmt.Sprintf("Subsystem %q (%s), against all ten principles.", *subsystem, path)
		lookFor = "every principle in CONSTITUTION.md — use each principle's Anti-examples and Compliance test"
		outName = fmt.Sprintf("subsystem-%s-%s.md", *subsystem, date)
		auditMode = firstNonEmpty(strings.ToUpper(*mode), "B")
	}

	fmt.Print(auditPrompt(auditMode, scope, lookFor, outName, date))
	return nil
}

func auditPrompt(mode, scope, lookFor, outName, date string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Tollwing audit prompt (mode %s) — generated %s ===\n\n", mode, date)
	b.WriteString(`You are auditing Tollwing against its constitution. Be uncompromising and
honest: report what is wrong, fully, without softening severity or biasing
toward fix-in-place to keep the codebase looking healthy. The cost of a rewrite
is not your concern — correctness is. You recommend; the maintainer decides.

REQUIRED READING (read fully before auditing):
  - CONSTITUTION.md
  - docs/governance/audit-playbook.md
  - docs/governance/conventions.md
  - decisions/README.md  (skim the index; read the ADRs relevant to the scope)

SCOPE:
  ` + scope + `
  Look for: ` + lookFor + `

TASK:
  1. Run the mechanical baseline first: ` + "`go run ./tools/governance scan`" + `.
     Treat it as a FLOOR, not a ceiling — it only sees the regex-detectable subset.
  2. Read the code in scope. For each violation record:
       - principle (Pn), severity (HIGH | MEDIUM | LOW), file:line,
       - what is wrong and why it violates the principle,
       - the recommended remediation path:
           1 fix now · 2 document an exception (ADR) · 3 propose an amendment ·
           4 accept as tracked debt · 5 rewrite / rebuild / kill.
  3. Severity is not impact: a HIGH in dead code is still a HIGH.
  4. If a violation is already covered by a // DEC-NNN exception, note it and move on.

OUTPUT:
  Write the report to reports/audits/` + outName + ` following the report
  template in the audit playbook (§ Report template). Then summarize the
  findings here, highest severity first.

AUDITOR'S COMMITMENT:
  If the right answer is "rewrite this", say so plainly. If you find nothing,
  say that and list exactly what you checked. Do not invent findings to look
  thorough, and do not suppress real ones to look reassuring.
`)
	return b.String()
}

func printAuditList() {
	fmt.Println("Principles (use with -principle):")
	keys := make([]string, 0, len(principles))
	for k := range principles {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return pnum(keys[i]) < pnum(keys[j]) })
	for _, k := range keys {
		fmt.Printf("  %-4s %s\n", k, principles[k].name)
	}
	fmt.Println("\nSubsystems (use with -subsystem):")
	subs := make([]string, 0, len(subsystems))
	for k := range subsystems {
		subs = append(subs, k)
	}
	sort.Strings(subs)
	for _, s := range subs {
		fmt.Printf("  %-12s %s\n", s, subsystems[s])
	}
}

func pnum(p string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(p, "P"))
	return n
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
