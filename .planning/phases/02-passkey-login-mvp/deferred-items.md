# Phase 02 deferred items

Out-of-scope discoveries during execution: logged here, not fixed in the plan that found them.

| Found in | Item | Why deferred |
|---|---|---|
| 02-01 | In WSL, `bash scripts/linux.sh 'go test ... && test -z "$(gofmt -l .)" && ...'` passes the gofmt step without checking anything. `gofmt` is not on the PATH of the WSL login shell (`gofmt: command not found`), and the command substitution expands in the outer Git Bash shell, so the test sees empty output. The plan's full gate therefore does not check formatting when run that way. CI's lint job runs gofmt properly. 02-01 checked formatting with the Windows toolchain's `gofmt -l .` and with `$(go env GOROOT)/bin/gofmt -l .` from a script file in WSL: both clean. | Environment quirk in the local gate command, not in 02-01's code. A fix (put `$(go env GOROOT)/bin` on the WSL PATH, or call the gate from a script file) belongs to whichever plan next edits the gate or `scripts/linux.sh`. |
