#!/usr/bin/env bash
# Run every native Go fuzz target in the module for FUZZTIME each.
#
#   FUZZTIME=30s bash scripts/fuzz.sh
#
# go test accepts one -fuzz target per invocation, so the targets are listed
# per package with `go test -list '^Fuzz'` and run one at a time. The script
# fails when any target fails (a failing input is written to the package's
# testdata/fuzz/<target>/ corpus, which is printed) and also when zero
# targets ran, so an empty fuzz job cannot pass silently.
set -euo pipefail

fuzztime=${FUZZTIME:-30s}
cd "$(git rev-parse --show-toplevel)"

ran=0
failed=()
while IFS=$'\t' read -r pkg dir; do
	# A package that does not compile must fail the job, not hide its targets.
	if ! listing=$(go test -list '^Fuzz' "$pkg"); then
		echo "fuzz: FAIL cannot list the fuzz targets of $pkg" >&2
		failed+=("$pkg (go test -list)")
		continue
	fi
	targets=$(printf '%s\n' "$listing" | grep -E '^Fuzz' || true)
	for target in $targets; do
		echo "fuzz: $pkg $target ($fuzztime)"
		ran=$((ran + 1))
		if ! go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg"; then
			echo "fuzz: FAIL $pkg $target; failing input corpus: $dir/testdata/fuzz/$target/" >&2
			failed+=("$pkg $target")
		fi
	done
done < <(go list -f '{{.ImportPath}}{{"\t"}}{{.Dir}}' ./...)

if [ "$ran" -eq 0 ]; then
	echo "fuzz: zero fuzz targets ran; refusing to pass an empty fuzz job" >&2
	exit 1
fi
if [ "${#failed[@]}" -ne 0 ]; then
	echo "fuzz: ${#failed[@]} of $ran targets failed:" >&2
	printf '  %s\n' "${failed[@]}" >&2
	exit 1
fi
echo "fuzz: all $ran targets passed ($fuzztime each)"
