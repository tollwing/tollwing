package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// finding is one mechanically-detected potential violation.
type finding struct {
	principle string
	blocking  bool
	path      string
	line      int
	msg       string
	excepted  bool // a // DEC-NNN citation on the line downgrades it to informational
}

var (
	// A line that is just a (possibly aliased/blank) import of the stdlib "log".
	// Precise on purpose: a file that imports "log" violates P9; a field or local
	// named log (e.g. w.log.Info) does not, so we key off the import, not the call.
	reLogImport = regexp.MustCompile(`^\s*(?:[A-Za-z0-9_.]+\s+)?"log"\s*$`)
	reDECcite   = regexp.MustCompile(`DEC-\d+`)
	// Destructive / history-rewriting ClickHouse DDL (P7).
	reDropSQL = regexp.MustCompile(`(?i)\b(?:DROP\s+(?:TABLE|COLUMN|DATABASE|VIEW)|RENAME\s+COLUMN|MODIFY\s+COLUMN)\b`)
)

// canonical traffic-type wire strings owned by classifier.TrafficType.String().
// A double-quoted occurrence outside the canonical file is a P6 drift risk.
var trafficTypeLiterals = []string{
	"same_zone", "cross_az", "cross_region", "internet_egress",
	"nat_gateway", "vpc_peering", "transit_gateway", "vpc_endpoint",
	"cloud_service_public",
}

// Dependencies banned by default under P9 — stdlib covers these. Adding any
// requires an ADR (DEC-005).
var bannedDeps = []string{
	"github.com/spf13/cobra",
	"github.com/spf13/viper",
	"github.com/stretchr/testify",
	"go.uber.org/zap",
	"github.com/sirupsen/logrus",
	"github.com/rs/zerolog",
	"github.com/urfave/cli",
}

const canonicalTrafficFile = "pkg/classifier/traffic.go"

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	gate := fs.Bool("gate", false, "exit non-zero on any blocking-class finding (for CI)")
	strict := fs.Bool("strict", false, "exit non-zero on any finding, blocking or not")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := repoRoot()
	if err != nil {
		return err
	}

	var findings []finding

	gomod, err := scanGoMod(root)
	if err != nil {
		return err
	}
	findings = append(findings, gomod...)

	for _, sub := range []string{"pkg", "cmd"} {
		walkErr := filepath.WalkDir(filepath.Join(root, sub), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry or missing tree — skip, don't fail the scan
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			fnd, ferr := scanGoFile(root, path)
			if ferr != nil {
				return ferr
			}
			findings = append(findings, fnd...)
			return nil
		})
		if walkErr != nil {
			return walkErr
		}
	}

	return report(findings, *gate, *strict)
}

func scanGoMod(root string) ([]finding, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	var out []finding
	for i, line := range strings.Split(string(data), "\n") {
		for _, dep := range bannedDeps {
			if strings.Contains(line, dep) {
				out = append(out, finding{
					principle: "P9", blocking: true, path: "go.mod", line: i + 1,
					msg:      fmt.Sprintf("banned dependency %q — stdlib-first; a new dep needs an ADR (DEC-005)", dep),
					excepted: reDECcite.MatchString(line),
				})
			}
		}
	}
	return out, nil
}

func scanGoFile(root, path string) ([]finding, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(rel)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	isTest := strings.HasSuffix(rel, "_test.go")
	isCanonicalTraffic := rel == canonicalTrafficFile
	inClickhouse := strings.HasPrefix(rel, "pkg/storage/clickhouse/")

	var out []finding
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		ln := i + 1
		excepted := reDECcite.MatchString(line)

		// P9 — stdlib "log" import.
		if reLogImport.MatchString(line) {
			out = append(out, finding{
				principle: "P9", blocking: true, path: rel, line: ln,
				msg: `imports stdlib "log" — use log/slog (DEC-005)`, excepted: excepted,
			})
		}

		// P6 — hardcoded traffic-type literal outside the canonical enum file.
		// Blocking since DEC-007 (the cleanup that drove the count to zero); an
		// inline DEC-NNN citation on the line marks a documented exception (INFO).
		if !isTest && !isCanonicalTraffic {
			for _, lit := range trafficTypeLiterals {
				if strings.Contains(line, `"`+lit+`"`) {
					out = append(out, finding{
						principle: "P6", blocking: true, path: rel, line: ln,
						msg:      fmt.Sprintf("hardcoded traffic-type literal %q — derive from classifier.TrafficType.String() (P6)", lit),
						excepted: excepted,
					})
				}
			}
		}

		// P7 — destructive / history-rewriting migration SQL.
		if inClickhouse && reDropSQL.MatchString(line) {
			out = append(out, finding{
				principle: "P7", blocking: false, path: rel, line: ln,
				msg:      "destructive/rewriting SQL — ClickHouse migrations are forward-only and additive (DEC-004)",
				excepted: excepted,
			})
		}
	}

	// P3 — cgo (`import "C"`) must stay behind a cgo/nvml/cuda build tag so the
	// server and CLI cross-compile CGO_ENABLED=0.
	if cl := cgoImportLine(lines); cl > 0 && !hasCgoBuildTag(lines) {
		out = append(out, finding{
			principle: "P3", blocking: true, path: rel, line: cl,
			msg:      `cgo import "C" without a cgo/nvml/cuda build tag — keep cgo behind build tags (P3)`,
			excepted: reDECcite.MatchString(lines[cl-1]),
		})
	}

	return out, nil
}

// cgoImportLine returns the 1-based line of a single `import "C"` (cgo), or 0.
func cgoImportLine(lines []string) int {
	for i, l := range lines {
		if strings.TrimSpace(l) == `import "C"` {
			return i + 1
		}
	}
	return 0
}

// hasCgoBuildTag reports whether the file is gated by a cgo/nvml/cuda build tag.
func hasCgoBuildTag(lines []string) bool {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "//go:build ") &&
			(strings.Contains(t, "cgo") || strings.Contains(t, "nvml") || strings.Contains(t, "cuda")) {
			return true
		}
	}
	return false
}

func report(findings []finding, gate, strict bool) error {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].path != findings[j].path {
			return findings[i].path < findings[j].path
		}
		return findings[i].line < findings[j].line
	})

	var blocking, warn, info int
	for _, f := range findings {
		tag := "WARN"
		switch {
		case f.excepted:
			tag, info = "INFO", info+1
		case f.blocking:
			tag, blocking = "BLOCK", blocking+1
		default:
			warn++
		}
		fmt.Printf("  [%-5s] %-3s %s:%d  %s\n", tag, f.principle, f.path, f.line, f.msg)
	}

	if blocking == 0 && warn == 0 {
		fmt.Println("scan: clean (no blocking or warn findings)")
	} else {
		fmt.Printf("\nscan: %d blocking, %d warn, %d excepted (informational)\n", blocking, warn, info)
	}

	switch {
	case strict && (blocking > 0 || warn > 0):
		return fmt.Errorf("strict: %d blocking + %d warn finding(s)", blocking, warn)
	case gate && blocking > 0:
		return fmt.Errorf("%d blocking-class violation(s) — fix or document an exception ADR", blocking)
	}
	return nil
}
