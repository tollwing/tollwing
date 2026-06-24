#!/usr/bin/env bash
# Point git at the repo's .githooks/ directory, enabling the warn-only
# governance pre-commit scan. Per DEC-001. Run once after cloning:
#
#   tools/governance/install-hooks.sh
#
# This is per-checkout and non-invasive (it only sets core.hooksPath). The hook
# warns but never blocks a commit — CI is the real gate. Bypass with --no-verify.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
git -C "$root" config core.hooksPath .githooks
echo "git core.hooksPath set to .githooks (warn-only governance scan on commit)"
