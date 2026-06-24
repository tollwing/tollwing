package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	indexBegin = "<!-- INDEX:BEGIN -->"
	indexEnd   = "<!-- INDEX:END -->"
)

// adr is one parsed decision record, used to render the index row.
type adr struct {
	num        int
	id         string // "DEC-001"
	file       string // "DEC-001-....md"
	title      string
	status     string
	date       string
	principles string // rendered cell: "P1, P2, P9" or "All ten" or "—"
}

var (
	// H1 separator is a space-em-dash-space; tolerate a plain hyphen too.
	reH1     = regexp.MustCompile(`^#\s+(DEC-\d+)\s+[—\-]\s+(.+?)\s*$`)
	reStatus = regexp.MustCompile(`(?m)^\*\*Status:\*\*\s+(.+?)\s*$`)
	reDate   = regexp.MustCompile(`(?m)^\*\*Date:\*\*\s+(\d{4}-\d{2}-\d{2})`)
	rePrinc  = regexp.MustCompile(`\bP(?:1[0-2]|[1-9])\b`)
	reAllTen = regexp.MustCompile(`(?i)\ball (?:ten|twelve)\b`)
	reNum    = regexp.MustCompile(`DEC-(\d+)`)
)

func runIndex(args []string) error {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	check := fs.Bool("check", false, "exit non-zero if the index is stale; do not write")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := repoRoot()
	if err != nil {
		return err
	}
	decisionsDir := filepath.Join(root, "decisions")
	readmePath := filepath.Join(decisionsDir, "README.md")

	adrs, err := collectADRs(decisionsDir)
	if err != nil {
		return err
	}

	cur, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("read decisions/README.md: %w", err)
	}
	updated, err := spliceIndex(string(cur), renderIndex(adrs))
	if err != nil {
		return err
	}

	if string(cur) == updated {
		if !*check {
			fmt.Printf("decision index up to date (%d decisions)\n", len(adrs))
		}
		return nil
	}
	if *check {
		return fmt.Errorf("decision index is stale — run `go run ./tools/governance index` and commit decisions/README.md")
	}
	if err := os.WriteFile(readmePath, []byte(updated), 0o644); err != nil {
		return err
	}
	fmt.Printf("decision index updated (%d decisions)\n", len(adrs))
	return nil
}

func collectADRs(decisionsDir string) ([]adr, error) {
	entries, err := os.ReadDir(decisionsDir)
	if err != nil {
		return nil, fmt.Errorf("read decisions/: %w", err)
	}
	var adrs []adr
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "DEC-") || !strings.HasSuffix(name, ".md") {
			continue
		}
		a, err := parseADR(filepath.Join(decisionsDir, name))
		if err != nil {
			return nil, err
		}
		adrs = append(adrs, a)
	}
	// Newest first.
	sort.Slice(adrs, func(i, j int) bool { return adrs[i].num > adrs[j].num })
	return adrs, nil
}

// parseADR reads one DEC-*.md and errors loudly if it does not conform to the
// template — a malformed ADR is a signal it was authored outside TEMPLATE.md.
func parseADR(path string) (adr, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return adr{}, err
	}
	content := string(raw)
	base := filepath.Base(path)

	// H1 is the first non-empty line.
	var h1 string
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) != "" {
			h1 = l
			break
		}
	}
	m := reH1.FindStringSubmatch(h1)
	if m == nil {
		return adr{}, fmt.Errorf("%s: first line is not a valid ADR title (want `# DEC-NNN — Title`), got %q", base, h1)
	}
	id, title := m[1], m[2]

	sm := reStatus.FindStringSubmatch(content)
	if sm == nil {
		return adr{}, fmt.Errorf("%s: missing `**Status:**` line", base)
	}
	dm := reDate.FindStringSubmatch(content)
	if dm == nil {
		return adr{}, fmt.Errorf("%s: missing or malformed `**Date:**` line (want YYYY-MM-DD)", base)
	}

	sec, ok := extractSection(content, "Constitutional principles touched")
	if !ok {
		return adr{}, fmt.Errorf("%s: missing `## Constitutional principles touched` section", base)
	}

	nm := reNum.FindStringSubmatch(id)
	num, _ := strconv.Atoi(nm[1])

	return adr{
		num:        num,
		id:         id,
		file:       base,
		title:      strings.ReplaceAll(title, "|", `\|`),
		status:     strings.TrimSpace(sm[1]),
		date:       dm[1],
		principles: renderPrinciples(sec),
	}, nil
}

// extractSection returns the body between "## <heading>" and the next "## ".
func extractSection(content, heading string) (string, bool) {
	lines := strings.Split(content, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "## "+heading {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return "", false
	}
	var b strings.Builder
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			break
		}
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}
	return b.String(), true
}

func renderPrinciples(section string) string {
	if reAllTen.MatchString(section) {
		return "All"
	}
	found := map[int]bool{}
	for _, p := range rePrinc.FindAllString(section, -1) {
		n, _ := strconv.Atoi(strings.TrimPrefix(p, "P"))
		found[n] = true
	}
	if len(found) == 0 {
		return "—"
	}
	nums := make([]int, 0, len(found))
	for n := range found {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = "P" + strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

func renderIndex(adrs []adr) string {
	var b strings.Builder
	b.WriteString(indexBegin)
	b.WriteByte('\n')
	b.WriteString("| ID | Title | Status | Date | Principles |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, a := range adrs {
		fmt.Fprintf(&b, "| [%s](%s) | %s | %s | %s | %s |\n",
			a.id, a.file, a.title, a.status, a.date, a.principles)
	}
	b.WriteString(indexEnd)
	return b.String()
}

func spliceIndex(readme, table string) (string, error) {
	bi := strings.Index(readme, indexBegin)
	ei := strings.Index(readme, indexEnd)
	if bi == -1 || ei == -1 || ei < bi {
		return "", fmt.Errorf("index markers %q / %q not found in decisions/README.md", indexBegin, indexEnd)
	}
	return readme[:bi] + table + readme[ei+len(indexEnd):], nil
}
