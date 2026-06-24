// Command governance is Tollwing's stdlib-only governance tool. It keeps the
// decision-log index in sync, scans the source for mechanically-detectable
// constitutional violations, and generates audit prompts.
//
// Per DEC-001, the tooling that enforces the constitution is itself Go and
// standard-library-only (P9) — shipping a different language to enforce a
// stdlib-first Go constitution would violate it. This package lives outside
// cmd/ so it is never built into a shipped product binary; invoke it with:
//
//	go run ./tools/governance <index|scan|audit> [flags]
//
// See decisions/README.md and docs/governance/audit-playbook.md.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "index":
		err = runIndex(args)
	case "scan":
		err = runScan(args)
	case "audit":
		err = runAudit(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "governance: unknown subcommand %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "governance %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `governance — Tollwing governance tooling (see decisions/README.md)

usage:
  go run ./tools/governance index [-check]
        Regenerate the decision index in decisions/README.md from the DEC-*.md
        files. -check verifies it is in sync (exits non-zero if stale) without
        writing — used by the CI governance job.

  go run ./tools/governance scan [-gate] [-strict]
        Scan pkg/ + cmd/ + go.mod for mechanically-detectable constitutional
        violations (P6/P7/P9). Default is warn-only. -gate fails on blocking-
        class findings (CI). -strict fails on any finding (honest local view).
        A finding on a line citing an exception (// DEC-NNN) is downgraded.

  go run ./tools/governance audit [-principle Pn] [-subsystem name] [-mode A|B|C|D] [-list]
        Generate a fully-specified audit prompt to paste into an AI agent.
        It never calls an LLM; it produces the prompt. See the audit playbook.
`)
}

// repoRoot finds the module root by walking up from the working directory until
// it finds go.mod. CI and the git hook invoke from the root, so this is almost
// always the working directory; the walk just makes the tool robust to cwd.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ".", nil // fall back to cwd
		}
		dir = parent
	}
}
