#!/usr/bin/env bash
set -euo pipefail
[[ -f go.mod ]] || { echo 'go.mod is required' >&2; exit 1; }
files=()
while IFS= read -r -d '' file; do files+=("$file"); done < <(git ls-files -z '*.go')
((${#files[@]} > 0)) || { echo 'go.mod exists but no tracked Go source exists' >&2; exit 1; }
unformatted=$(gofmt -l "${files[@]}")
if [[ -n "$unformatted" ]]; then
  printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
  exit 1
fi
# Dependencies may be downloaded in preparation; test execution itself is offline.
go mod download
go mod verify
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
go vet ./...
go test -count=1 -timeout=5m ./...
git diff --exit-code -- go.mod go.sum
