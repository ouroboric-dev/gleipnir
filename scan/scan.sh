#!/bin/bash
# scan.sh: look for secrets in what a checkpoint would commit (spec §14). Run in the leaf's sandbox, in
# the leaf's top folder. It copies the files git would add (changed and new, apart from the ones
# .gitignore names) to a scratch folder, and runs gitleaks over them with every match redacted. Exit
# 0: nothing found. Exit 7: secrets found, as a JSON report on standard output. Anything else: the scan
# itself failed, which counts as a failure to scan and never as a clean tree.
set -euo pipefail
d="$(mktemp -d)"
trap 'rm -rf "$d"' EXIT
while IFS= read -r -d '' f; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    cp --parents -- "$f" "$d"
  fi
done < <(git ls-files -z --modified --others --exclude-standard)
cd "$d" # so the report names files by their path in the leaf, not in a scratch folder
gitleaks dir --no-banner --redact --exit-code 7 --report-format json --report-path /dev/stdout .
