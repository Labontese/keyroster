//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// replayExtractScript is the extraction step of docs/runbooks/signer-install.md
// "A restore brings back the older trust bundle, policy and directory",
// step 3, verbatim after the runbook's three variable assignments (V, SAVED
// and D, which the test passes in the environment). The runbook runs it in
// bash -eu from a heredoc (replayExtractBlock), and so does the test, so
// that a failing line stops it for an operator as it does here. Keep the
// two in sync: TestRestoreReplaysLostDirectory runs this text, so it is
// the runbook's command that is run in CI e2e, not a reimplementation of
// it, and requireReplayBlock checks that the runbook still has it.
const replayExtractScript = `mkdir -p "$D"
grep '"kind":"directory_install"' "$SAVED" | grep -E ",\"version\":$V[,}]" > "$D/line"
test "$(wc -l < "$D/line")" -eq 1
grep -o '"directory":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json"
grep -o '"sigs":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json.sigs"
test -s "$D/directory.json"
test -s "$D/directory.json.sigs"
rm "$D/line"
echo "wrote the proposal of directory version $V to $D"
`

// replayExtractBlock is the runbook's whole extraction block: the bash
// -eu heredoc with the three variable assignments and replayExtractScript.
const replayExtractBlock = "bash -eu <<'EOF'\n" +
	"V=2                                   # the lost directory version\n" +
	"SAVED=/root/latest-saved.jsonl\n" +
	"D=/root/replay/v$V\n" +
	replayExtractScript +
	"EOF\n"

// requireReplayBlock: the runbook has replayExtractBlock as whole,
// consecutive lines, indented as the code block of step 3's first item.
func requireReplayBlock(t *testing.T, runbook string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(replayExtractBlock, "\n"), "\n")
	for i := range lines {
		lines[i] = "        " + lines[i]
	}
	if !strings.Contains(runbook, "\n"+strings.Join(lines, "\n")+"\n") {
		t.Fatalf("signer-install.md step 3 no longer has the extraction block that TestRestoreReplaysLostDirectory runs:\n%s", replayExtractBlock)
	}
}

// restoreRunbookChecks are the instructions of the same runbook section
// that TestRestoreReplaysLostDirectory carries out with its own pins and
// paths (exportLog and auditVerifyPins) rather than as the runbook's text:
// step 1's export of the restored log, step 2's audit verify of the
// restored export on its own and its two audit verify runs of the saved
// export, step 3's copy of the proposal to the admin and the install of
// that copy, and the export and the two audit verify runs of the
// post-replay log ("After the replay, the new export is the baseline").
// TestRestoreRunbookChecks requires each in the runbook, so removing one
// of these instructions fails the e2e suite as removing an extraction
// line does.
var restoreRunbookChecks = []string{
	"--out /tmp/restored.jsonl",
	restoreVerify + "\n/tmp/restored.jsonl",
	restoreVerify + "\n/root/latest-saved.jsonl",
	restoreVerify + "\n--previous /tmp/restored.jsonl /root/latest-saved.jsonl",
	restoreAdminInstall,
	"`--out /tmp/after-replay.jsonl`",
	restoreVerify + "\n/tmp/after-replay.jsonl",
	restoreVerify + "\n--previous /tmp/restored.jsonl /tmp/after-replay.jsonl",
}

// restoreAdminCopyScript is step 3's copy of the proposal from /root,
// which is mode 0700, to the admin who installs it (round 4), after its
// heredoc line, which names the admin (<admin> in the runbook, kradmin in
// test/systemd/smoke.sh, which runs it). Since round 5 it writes as the
// admin with runuser and root only reads its own files, because the admin
// can plant a link where root would write. restoreAdminInstall is the
// install of that copy. restoreRootInstall, the install straight from
// /root/replay that no admin account can read, must not be in the
// runbook, and neither may a command of root's that creates, changes or
// writes an admin's path (restoreAdminPathWrite; round 4's install -d -o
// <admin> and install -o <admin> followed a planted link).
const (
	restoreAdminCopyScript = `V=2                                   # the lost directory version
H=$(getent passwd "$1" | cut -d: -f6)
test -n "$H"
runuser -u "$1" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/replay-v$V"
for f in directory.json directory.json.sigs; do
  runuser -u "$1" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/replay-v$V/$f" <"/root/replay/v$V/$f"
done
echo "copied the proposal of directory version $V to $H/replay-v$V for $1"
EOF`
	restoreAdminInstall = "keyroster directory install /home/<admin>/replay-v2"
	restoreRootInstall  = "keyroster directory install /root/replay"
)

var restoreAdminPathWrite = regexp.MustCompile(`(?m)^[ \t]*(?:install|chown|chmod|cp|mv|mkdir|ln|tee|touch)\b[^\n]*(?:<admin>|/home/)`)

// restoreVerify is the first line of the runbook's audit verify commands.
const restoreVerify = `keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \`

// The order and the condition of step 2's verification of the saved
// export (03-02 pre-merge review, round 3): it runs whenever step 2's
// first command fails, whatever that reports, and before any grep reads
// the saved export.
const (
	// restoreRestoredVerify is step 2's audit verify of the restored
	// export on its own (round 4), and restoreRestoredStop what to do when
	// it fails. Both come before step 2's first comparison: Verify reports
	// log shrank or log rewritten only after the restored export verified,
	// but any other refusal of the comparison may come from the restored
	// export itself.
	restoreRestoredVerify = restoreVerify + "\n/tmp/restored.jsonl"
	restoreRestoredStop   = "It must pass. If it fails, do not compare it with anything and read nothing from it: stop there"
	// restoreFirstCheck is the end of step 2's first comparison.
	restoreFirstCheck = `--previous /root/latest-saved.jsonl /tmp/restored.jsonl`
	// restoreSavedVerify is the two audit verify runs of the saved export.
	restoreSavedVerify = restoreVerify + "\n/root/latest-saved.jsonl\n" +
		restoreVerify + "\n--previous /tmp/restored.jsonl /root/latest-saved.jsonl"
	// restoreSavedVerifyIf is the condition the runbook puts on them.
	restoreSavedVerifyIf = "If it fails, whatever it reports (`log shrank`, `log rewritten` or another refusal), verify the saved export itself"
	// restoreSavedStop is what to do when either fails.
	restoreSavedStop = "Both must pass. If either fails, do not use the saved export at all"
	// restoreShrankGate is the condition of 894a6c3, under which a saved
	// export reported as rewritten was read unverified.
	restoreShrankGate = "When it reports `log shrank`"
)

// The restore hold (owner decision 2026-10-25, PR #59 review round 4): a
// drop-in that makes every start of keyroster-signer and keyroster-server
// fail, written before the restored signer.db is copied in and before
// step 1, and removed at the end of step 2, before step 3 starts the
// signer. The hold, file restore and release blocks are the runbook's and
// test/systemd/smoke.sh's (the systemd-sandbox CI job runs them on the
// repository's units); TestRestoreRunbookChecks requires each in both.
const (
	restoreHoldUnits = "bash -eu -s keyroster-server keyroster-signer <<'EOF'\n"
	restoreHoldBlock = restoreHoldUnits +
		`test "$#" -gt 0
for u in "$@"; do
  install -d -m 0755 "/etc/systemd/system/$u.service.d"
  printf '[Unit]\nAssertPathExists=/nonexistent-restore-hold\n' >"/etc/systemd/system/$u.service.d/restore-hold.conf"
done
systemctl daemon-reload
for u in "$@"; do
  systemctl stop "$u.service"
done
for u in "$@"; do
  test "$(systemctl show -p LoadState --value "$u.service")" = loaded
  systemctl show -p DropInPaths --value "$u.service" | grep -q "/$u.service.d/restore-hold.conf"
  if systemctl start "$u.service"; then
    systemctl stop "$u.service"
    echo "$u.service started: the hold is NOT in force" >&2
    exit 1
  fi
done
echo "held: $*"
EOF`
	// restoreFilesScript is the file restore after its heredoc line, which
	// names the backup directory (<backup> in the runbook).
	restoreFilesScript = `S=/var/lib/keyroster-signer
test -e /etc/systemd/system/keyroster-signer.service.d/restore-hold.conf
st=$(systemctl show -p ActiveState --value keyroster-signer.service)
if [ "$st" != inactive ] && [ "$st" != failed ]; then
  echo "keyroster-signer.service is $st: hold it first" >&2
  exit 1
fi
exec 9<"$S/signer.lock"
if ! flock -n 9; then
  echo "$S is in use by another keyroster-signer process" >&2
  exit 1
fi
test -s "$1/signer.db"
rm -f "$S/signer.db" "$S/signer.db-wal" "$S/signer.db-shm"
for f in signer.db signer.db-wal signer.db-shm; do
  if [ -e "$1/$f" ]; then
    install -o keyroster-signer -g keyroster-signer -m 0600 "$1/$f" "$S/$f"
  fi
done
echo "restored signer.db from $1"
EOF`
	restoreReleaseBlock = restoreHoldUnits +
		`test "$#" -gt 0
for u in "$@"; do
  rm "/etc/systemd/system/$u.service.d/restore-hold.conf"
done
systemctl daemon-reload
for u in "$@"; do
  if systemctl is-failed --quiet "$u.service"; then systemctl reset-failed "$u.service"; fi
done
echo "released: $*"
EOF`
	// restoreStep1 and restoreStep3 open the runbook's steps 1 and 3.
	restoreStep1 = "1. With the hold in force, export the restored log:"
	restoreStep3 = "3. Reinstall what the restore lost"
	// restoreVMNoBoot and restoreVMRAM are the disk-only VM restore's rule
	// (owner decision 2026-10-25, PR #59 review round 5: the snapshot is
	// never booted; its files are restored on the current signer VM) and
	// the rule for a snapshot with RAM, both before step 1.
	// restoreVMBooted are round 4's commands that roll back and boot the
	// signer VM, which the runbook must no longer have.
	restoreVMNoBoot = "From a disk-only VM snapshot (Proxmox): never boot the snapshot."
	restoreVMRAM    = "A VM snapshot with RAM is not supported for the signer VM."
	// restoreSavedSource is step 2's rule for where the saved export comes
	// from, before the first comparison reads it.
	restoreSavedSource = "That saved export must come from storage that no restore rolled back"
	// restoreRevokeStop is 03-03's stop for a restore that lost a
	// revocation, and restoreRevokeInterim its text saying that the runbook
	// did not recover lost revocations yet. 03-06c replaced both with step
	// 2b, which recovers after every restore; neither may come back.
	restoreRevokeStop    = "the restore lost a revocation: do not release the hold"
	restoreRevokeInterim = "Until the restore-recovery plan merges"
	// restoreSavedExportRule is the operating rule that stays (T-03-207):
	// a revocation after the latest saved export is in neither export.
	restoreSavedExportRule = "take a saved export after every revocation"
)

// The recovery of the revocations a restore lost (03-06c, after 03-06b's
// commands): the capture block right after the hold's held: line, step
// 2b's clock check, copy block, the admin's keyroster revoke recover, the
// read-back block and the recovery line under the hold, then the release.
// The capture, copy, read-back and recovery blocks are the runbook's and
// test/systemd/smoke.sh's (the systemd-sandbox job runs them);
// TestRestoreRunbookChecks requires each in both, and their order.
// TestRestoreRecoversLostRevocations carries out the same steps with the
// test's own user and paths.
const (
	// restoreCaptureBlock keeps keyroster-server's krl-served.json, read
	// as keyroster-server. It prints exactly one of restoreCaptureKept and
	// restoreCaptureNone, and the second only once the server account
	// reached its state directory (PR #66 plan check).
	//
	// PR #70 review (F5, F15): it decides that the file is absent only
	// from a listing that succeeded (find exits non-zero on an error, and
	// -e stops the block), and copies only a regular file (after links,
	// as the server account sees it) of at most krl.MaxKRLResponse bytes,
	// the most keyroster revoke recover reads from a --krl file
	// (TestRestoreCopyCaps), so a link to /dev/zero or a FIFO stops it.
	//
	// PR #70 review round 2: find -H lists the state directory also when
	// it is itself a link (state kept on another disk, say). Without -H,
	// find does not descend through a linked start point, prints nothing
	// and exits 0, and the block claims that a kept file does not exist.
	// -H follows only that start point, so a krl-served.json that is a
	// link is still listed, and test -f decides about it.
	restoreCaptureBlock = "bash -eu <<'EOF'\n" +
		`runuser -u keyroster-server -- test -d /var/lib/keyroster-server -a -x /var/lib/keyroster-server
test ! -e /root/recovery
install -d -m 0700 /root/recovery
listed=$(runuser -u keyroster-server -- find -H /var/lib/keyroster-server -maxdepth 1 -name krl-served.json -print)
if [ -n "$listed" ]; then
  runuser -u keyroster-server -- test -f /var/lib/keyroster-server/krl-served.json
  runuser -u keyroster-server -- head -c 5620745 /var/lib/keyroster-server/krl-served.json > /root/recovery/server-krl.json
  test -s /root/recovery/server-krl.json
  test "$(stat -c %s /root/recovery/server-krl.json)" -le 5620744
  echo "kept: /root/recovery/server-krl.json"
else
  echo "no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist"
fi
EOF`
	restoreCaptureKept = "kept: /root/recovery/server-krl.json"
	restoreCaptureNone = "no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist"
	// restoreServerCopyTrust is D-R2's residual next to the capture block:
	// the copy is only as trustworthy as the server account, and the
	// cross-check against the hosts (03-07, T-03-277) runs before step 2b.
	restoreServerCopyTrust = "**The copy is only as trustworthy as the keyroster-server account.**"
	restoreServerCopyCheck = "The cross-check below compares the copy with the KRL the enrolled hosts enforce (T-03-277). Run it before step 2b."
	// restoreCrossCheckHead heads the cross-check (03-07, T-03-277, owner
	// decision D-R2): restoreCrossCheckCommand prints each host's KRL
	// version, restoreCrossCheckBlock compares them with the kept copy's,
	// restoreCrossCheckRule makes its line step 2b's gate, and
	// restoreCrossCheckResidual names what it cannot see.
	restoreCrossCheckHead     = "**Cross-check the copy against the hosts (T-03-277).**"
	restoreCrossCheckCommand  = "keyroster-agent krl-version"
	restoreCrossCheckLine     = "It prints one line, `installed KRL version: <N>`, and changes nothing"
	restoreCrossCheckOpener   = "bash -eu -s <host KRL version> [<host KRL version> ...] <<'EOF'\n"
	restoreCrossCheckRule     = "Only the last line's `cross-check passed:` lets step 2b run;"
	restoreCrossCheckGate     = "and only after the cross-check of the server copy against the hosts printed `cross-check passed:` (T-03-277)."
	restoreCrossCheckNoCopy   = "After the capture block printed `no server KRL copy`, the copy counts as version 0, so any host that enforces a KRL stops the block"
	restoreCrossCheckResidual = "The cross-check cannot help where no host is enrolled, or where every host you reach is under the same control as the keyroster-server account"
	// restoreCrossCheckWithheld and restoreCrossCheckEscalate are the
	// residual's withholding case and its unconditional escalation (PR #71
	// review F6): a server that froze KRL delivery before it rolled back
	// its copy passes the check.
	restoreCrossCheckWithheld = "Nor can it catch a keyroster-server account that withheld KRLs from the hosts before it rolled back its copy"
	restoreCrossCheckEscalate = "A passing cross-check therefore never clears a suspected compromise of the server host: escalate every restore after a suspected compromise of the server host, whatever the cross-check prints."
	restoreCrossCheckProves   = "That is all a passing cross-check proves: the copy is at least as new as the KRL every host you checked enforces."
	// restoreCrossCheckScript is the block after its heredoc line and its
	// assignment (restoreCrossCheckBlock), which TestRestoreCrossCheck and
	// TestAgentEnrollEndToEnd run with KEPT in the environment.
	restoreCrossCheckScript = `set -o pipefail
stop() { echo "cross-check: $*" >&2; exit 1; }
[ "$#" -gt 0 ] || stop "no host's installed KRL version given; run keyroster-agent krl-version on at least one enrolled host"
v=0
if [ -e "$KEPT" ]; then
  [ "$(wc -l <"$KEPT")" -eq 1 ] || stop "$KEPT is not one line"
  grep -Eqx '\{"krl":"[A-Za-z0-9+/=]+","manifest":"[A-Za-z0-9+/=]+","sig":"[A-Za-z0-9+/=]+"\}' "$KEPT" || stop "$KEPT is not a KRL document as keyroster-server writes it"
  v=$(cut -d'"' -f8 "$KEPT" | base64 -d | grep -o '"krl_version":[0-9]*' | cut -d: -f2) || stop "$KEPT has no KRL version"
fi
for n in "$v" "$@"; do
  case "$n" in '' | *[!0-9]* | 0?* | ???????????????????*) stop "'$n' is not a KRL version" ;; esac
done
for h in "$@"; do
  [ "$h" -le "$v" ] || stop "a host enforces KRL v$h, above v$v of the kept server copy: the copy was rolled back or removed. Keep the hold and escalate"
done
echo "cross-check passed: the kept server copy's KRL v$v is at least every host's installed KRL version ($*)"
`
	restoreCrossCheckBlock = restoreCrossCheckOpener +
		"KEPT=/root/recovery/server-krl.json\n" +
		restoreCrossCheckScript +
		"EOF"
	// restoreClockCheck heads step 2b's clock check, which comes before
	// the recovery because the recovery publishes (T-03-273), and
	// restoreClockCommands and restoreClockRule are its commands and its
	// rule (PR #70 review, F11).
	restoreClockCheck    = "Check the clock, under the hold, before the recovery."
	restoreClockCommands = `timedatectl                                  # "System clock synchronized: yes"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
keyroster-signer doctor --state-dir /var/lib/keyroster-signer`
	restoreClockRule = "Go on only when `timedatectl` reports a synchronized clock and `doctor` shows `OK clock`"
	// restoreAdminOpener and restoreSmokeAdminOpener open the copy-in and
	// read-back blocks in the runbook (<admin>) and in smoke.sh (kradmin):
	// without -e a failing line no longer stops them (PR #70 review, F11).
	restoreAdminOpener      = "bash -eu -s <admin> <<'EOF'\n"
	restoreSmokeAdminOpener = "bash -eu -s kradmin <<'EOF'\n"
	// restoreCopyInScript is step 2b's copy of the two exports and, when
	// the capture block kept it, the server copy to the admin, after its
	// heredoc line, which names the admin (<admin> in the runbook, kradmin
	// in smoke.sh). It writes as the admin, as restoreAdminCopyScript does.
	restoreCopyInScript = `A=$1
H=$(getent passwd "$A" | cut -d: -f6)
test -n "$H"
test -d /root/recovery
runuser -u "$A" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/recovery-in"
copy_in() {
  runuser -u "$A" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/recovery-in/$1" <"$2"
}
copy_in restored.jsonl /tmp/restored.jsonl
copy_in latest-saved.jsonl /root/latest-saved.jsonl
files="restored.jsonl latest-saved.jsonl"
if [ -e /root/recovery/server-krl.json ]; then
  copy_in server-krl.json /root/recovery/server-krl.json
  files="$files server-krl.json"
fi
echo "copied $files to $H/recovery-in for $A"
EOF`
	// restoreAdminRecover is the admin's command, with --krl; restoreKRLRule
	// the rule that --krl is left out only after restoreCaptureNone, and
	// restoreReleaseRule the rule that a nothing to recover after
	// restoreCaptureKept keeps the hold (PR #66 plan check).
	restoreAdminRecover = `keyroster revoke recover --restored /home/<admin>/recovery-in/restored.jsonl \
--saved /home/<admin>/recovery-in/latest-saved.jsonl \
--krl /home/<admin>/recovery-in/server-krl.json \
--out /home/<admin>/recovery-in/recovery.bin`
	restoreKRLRule     = "Leave out `--krl ...` only when the capture block printed `no server KRL copy`."
	restoreReleaseRule = "Release the hold only when the capture block printed `no server KRL copy`. After `kept:`, a `nothing to recover` keeps the hold"
	// restoreImportRule is part 3's form of the server copy's import line
	// when the copy is the saved export's last KRL, as keyroster revoke
	// recover prints it (PR #70 review, F1; TestRestoreRecoveryAfterRecovery
	// requires that output).
	restoreImportRule = "with `same as saved export, log entry <n>, imported once`"
	// restoreReadBackScript is step 2b's read-back of the admin's request,
	// after its heredoc line: root reads it as the admin and writes only
	// /root/recovery. PR #70 review: it says why it stops over an earlier
	// request (F6), and copies only a regular file (after links, as the
	// admin sees it) of at most wire.MaxRecoveryFile bytes, the most
	// recover-revocations reads (F15, TestRestoreCopyCaps).
	restoreReadBackScript = `H=$(getent passwd "$1" | cut -d: -f6)
test -n "$H"
if [ -e /root/recovery/recovery.bin ]; then
  echo "/root/recovery/recovery.bin exists: move the refused request aside first (step 2b)" >&2
  exit 1
fi
runuser -u "$1" -- test -f "$H/recovery-in/recovery.bin"
runuser -u "$1" -- head -c 9470227 "$H/recovery-in/recovery.bin" > /root/recovery/recovery.bin
test -s /root/recovery/recovery.bin
test "$(stat -c %s /root/recovery/recovery.bin)" -le 9470226
echo "read the recovery request back to /root/recovery/recovery.bin"
EOF`
	// restoreRecoverLine applies the request under the hold.
	restoreRecoverLine = `runuser -u keyroster-signer -g keyroster-signer -G tss -- \
keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin`
	// restoreReleaseCheckScript is part 5's release check after its
	// heredoc line and its three assignments (restoreReleaseCheckBlock),
	// which TestRestoreRecoversLostRevocations and
	// TestRestoreRecoveryAfterRecovery run on their exports (PR #70
	// review, F2 and F3/D-R1): the recovered log holds exactly two
	// entries after the restored one, a revocation_recovery and a
	// krl_publish, and, when a server copy was kept, the recovery imported
	// its KRL version. restoreReleaseCheckRule is what its output must be.
	restoreReleaseCheckScript = `set -o pipefail
stop() { echo "release check: $*" >&2; exit 1; }
test -s "$RESTORED"
test -s "$RECOVERED"
n=$(($(wc -l <"$RESTORED") - 1))
[ "$(wc -l <"$RECOVERED")" -eq $((n + 3)) ] || stop "$RECOVERED does not hold exactly two entries after the $n of $RESTORED"
[ "$(sed -n "$((n + 1))p" "$RECOVERED" | grep -c "^{\"index\":$n,.*\"kind\":\"revocation_recovery\"")" = 1 ] || stop "entry $n is not a revocation_recovery"
[ "$(sed -n "$((n + 2))p" "$RECOVERED" | grep -c "^{\"index\":$((n + 1)),.*\"kind\":\"krl_publish\"")" = 1 ] || stop "entry $((n + 1)) is not a krl_publish"
imported=$(sed -n "$((n + 1))p" "$RECOVERED" | grep -o '"import_krl_versions":\[[0-9,]*\]' | tr -dc '0-9,') || stop "entry $n names no imported KRL versions"
if [ -e "$KEPT" ]; then
  [ "$(wc -l <"$KEPT")" -eq 1 ] || stop "$KEPT is not one line"
  grep -Eqx '\{"krl":"[A-Za-z0-9+/=]+","manifest":"[A-Za-z0-9+/=]+","sig":"[A-Za-z0-9+/=]+"\}' "$KEPT" || stop "$KEPT is not a KRL document as keyroster-server writes it"
  v=$(cut -d'"' -f8 "$KEPT" | base64 -d | grep -o '"krl_version":[0-9]*' | cut -d: -f2) || stop "$KEPT has no KRL version"
  case "$v" in '' | *[!0-9]*) stop "$KEPT has no single KRL version" ;; esac
  printf '%s\n' "$imported" | tr , '\n' | grep -x "$v" >/dev/null || stop "the recovery did not import the kept server copy, KRL v$v (it imported KRL versions [$imported])"
  echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], the kept server copy's v$v among them"
else
  echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], no server KRL copy kept"
fi
`
	restoreReleaseCheckBlock = "bash -eu <<'EOF'\n" +
		"RESTORED=/tmp/restored.jsonl\n" +
		"RECOVERED=/tmp/recovered.jsonl\n" +
		"KEPT=/root/recovery/server-krl.json\n" +
		restoreReleaseCheckScript +
		"EOF"
	restoreReleaseCheckRule = "Only the last line's `release check passed:` counts, and its two entries must be the `log entries <i>, <j>` of the `recovered:` line."
	restoreReleaseCheckStop = "If either verify fails or the release check stops, keep the hold and escalate."
	// restoreArchiveBlock moves a refused request aside inside
	// /root/recovery before a new one is read back (PR #70 review, F6),
	// and restoreArchiveRule says never to delete it or /root/recovery.
	restoreArchiveBlock = "bash -eu <<'EOF'\n" +
		`test -f /root/recovery/recovery.bin
d=/root/recovery/refused-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 0700 "$d"
mv /root/recovery/recovery.bin "$d/recovery.bin"
echo "moved the refused request to $d/recovery.bin"
EOF`
	restoreArchiveRule = "Never delete it, and never remove `/root/recovery`, which holds the kept server copy."
	// restoreOtherAdminRule is the refusal recovery_evidence_invalid's
	// remedy: another admin starts from part 2, which copies the inputs
	// to them (PR #70 review, F6).
	restoreOtherAdminRule = "Move the refused request aside (below), and have one who is make and sign it again, from part 2 on, which copies the inputs to that admin."
	// restoreReleaseAfter2b is the release paragraph's condition, and
	// restoreReleaseCases its two cases (PR #70 review, F9).
	restoreReleaseAfter2b = "**Release the hold** only after step 2b, in one of two cases:"
	restoreReleaseCase1   = "- the recovery's two `audit verify` runs passed and the release check printed `release check passed:`;"
	restoreReleaseCase2   = "- `keyroster revoke recover` printed `nothing to recover` after the capture block printed `no server KRL copy`."
	// restoreRemoteRelease is the release of a keyroster-server held on
	// another host (PR #70 review, F7), labelled UNVERIFIED.
	restoreRemoteRelease = "run the release block naming only `keyroster-server`, and start `keyroster-server.service` there. (UNVERIFIED: no test releases a server held on another host.)"
)

// restoreRecoveryChecks are step 2b's export of the recovered log and its
// two audit verify runs, which TestRestoreRecoversLostRevocations carries
// out with its own pins and paths, in this order; the release check
// (restoreReleaseCheckBlock) follows them.
var restoreRecoveryChecks = []string{
	"keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/recovered.jsonl",
	restoreVerify + "\n/tmp/recovered.jsonl",
	restoreVerify + "\n--previous /tmp/restored.jsonl /tmp/recovered.jsonl",
}

// runReleaseCheck runs the runbook's release check
// (restoreReleaseCheckScript) with bash -eu on restored, recovered and
// kept, as the runbook's block does with its three paths, and returns its
// exit code and combined output.
func runReleaseCheck(t *testing.T, restored, recovered, kept string) (int, string) {
	t.Helper()
	requireRunbookBlock(t, restoreReleaseCheckBlock)
	cmd := exec.Command("bash", "-eu")
	cmd.Stdin = strings.NewReader(restoreReleaseCheckScript)
	cmd.Env = append(os.Environ(), "RESTORED="+restored, "RECOVERED="+recovered, "KEPT="+kept)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("the runbook's release check: %v\n%s", err, out)
		}
		return ee.ExitCode(), string(out)
	}
	return 0, string(out)
}

// runCrossCheck runs the runbook's cross-check (restoreCrossCheckScript)
// with bash -eu on kept and the host versions, as the runbook's block does
// with /root/recovery/server-krl.json, and returns its exit code and
// combined output.
func runCrossCheck(t *testing.T, kept string, hosts ...string) (int, string) {
	t.Helper()
	requireRunbookBlock(t, restoreCrossCheckBlock)
	cmd := exec.Command("bash", append([]string{"-eu", "-s"}, hosts...)...)
	cmd.Stdin = strings.NewReader(restoreCrossCheckScript)
	cmd.Env = append(os.Environ(), "KEPT="+kept)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("the runbook's cross-check: %v\n%s", err, out)
		}
		return ee.ExitCode(), string(out)
	}
	return 0, string(out)
}

// keptCopy writes a KRL document of version v as keyroster-server writes
// krl-served.json (one line, the three fields) and returns its path.
func keptCopy(t *testing.T, v uint64) string {
	t.Helper()
	m := krl.Manifest{InstallationID: strings.Repeat("ab", 16), KRLVersion: v, KRLSHA256: krl.SHA256Hex([]byte("krl")),
		IssuedAt: "2026-10-28T12:00:00Z", BundleVersion: 1, LogIndex: 2}
	manifest, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(serverclient.KRLDocument{KRL: []byte("krl"), Manifest: manifest, Sig: []byte("sig")})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "server-krl.json")
	if err := os.WriteFile(p, append(doc, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRestoreCrossCheck (03-07, T-03-277, owner decision D-R2): the
// runbook's cross-check passes only when the kept server copy's KRL
// version is at least every host's installed version, refuses a host
// above it (a rolled-back copy), counts a missing copy as version 0 (a
// removed copy), and refuses no host and anything that is not a version.
func TestRestoreCrossCheck(t *testing.T) {
	kept := keptCopy(t, 1793000123)
	none := filepath.Join(t.TempDir(), "server-krl.json")
	for _, c := range []struct {
		name  string
		kept  string
		hosts []string
		pass  bool
		want  string
	}{
		{"equal", kept, []string{"1793000123"}, true, "cross-check passed: the kept server copy's KRL v1793000123 is at least every host's installed KRL version (1793000123)"},
		{"below_and_equal", kept, []string{"1793000001", "1793000123", "0"}, true, "cross-check passed:"},
		{"one_host_above", kept, []string{"1793000001", "1793000124"}, false, "a host enforces KRL v1793000124, above v1793000123 of the kept server copy"},
		{"no_copy_no_krl", none, []string{"0"}, true, "cross-check passed: the kept server copy's KRL v0"},
		{"no_copy_host_has_krl", none, []string{"1793000001"}, false, "a host enforces KRL v1793000001, above v0"},
		{"no_host", kept, nil, false, "no host's installed KRL version given"},
		{"not_a_number", kept, []string{"17930001x"}, false, "is not a KRL version"},
		{"leading_zero", kept, []string{"01793000999"}, false, "is not a KRL version"},
		{"too_long", kept, []string{"9999999999999999999999"}, false, "is not a KRL version"},
		{"empty", kept, []string{""}, false, "is not a KRL version"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := runCrossCheck(t, c.kept, c.hosts...)
			if (code == 0) != c.pass || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, want pass %t:\n%s", code, c.pass, out)
			}
			if !c.pass && strings.Contains(out, "cross-check passed") {
				t.Fatalf("a refused cross-check printed its pass line:\n%s", out)
			}
		})
	}
	// A copy that is not the server's one-line document stops the block.
	bad := filepath.Join(t.TempDir(), "server-krl.json")
	if err := os.WriteFile(bad, []byte("{\"krl\":\"a\"}\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCrossCheck(t, bad, "1"); code == 0 || !strings.Contains(out, "is not one line") {
		t.Fatalf("a two-line copy: exit %d:\n%s", code, out)
	}
}

// requireRunbookBlock: signer-install.md has block as whole lines, with
// every line's leading and trailing space trimmed.
func requireRunbookBlock(t *testing.T, block string) {
	t.Helper()
	trim := func(s string) string {
		l := strings.Split(s, "\n")
		for i := range l {
			l[i] = strings.TrimSpace(l[i])
		}
		return strings.Join(l, "\n")
	}
	runbook := "\n" + trim(string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))) + "\n"
	if !strings.Contains(runbook, "\n"+trim(block)+"\n") {
		t.Fatalf("signer-install.md no longer has the block this test runs:\n%s", block)
	}
}

// TestRestoreCopyCaps (PR #70 review, F15): the capture block copies at
// most krl.MaxKRLResponse bytes, the most keyroster revoke recover reads
// from a --krl file, and the read-back at most wire.MaxRecoveryFile, the
// most recover-revocations reads: each reads one byte more and refuses a
// copy above its limit, so no legitimate file is refused and no copy
// grows past the limit plus one byte.
func TestRestoreCopyCaps(t *testing.T) {
	for _, c := range []struct {
		name, block, file string
		limit             int
	}{
		{"capture", restoreCaptureBlock, "/root/recovery/server-krl.json", krl.MaxKRLResponse},
		{"read-back", restoreReadBackScript, "/root/recovery/recovery.bin", wire.MaxRecoveryFile},
	} {
		for _, want := range []string{
			"-- head -c " + strconv.Itoa(c.limit+1) + " ",
			`test "$(stat -c %s ` + c.file + `)" -le ` + strconv.Itoa(c.limit) + "\n",
		} {
			if !strings.Contains(c.block, want) {
				t.Errorf("the %s block lacks %q (its limit is %d bytes)", c.name, want, c.limit)
			}
		}
	}
}

var restoreVMBooted = []string{"link_down", "qm rollback <id>", "qm start <id>"}

// restoreSavedGreps are the runbook's greps of the saved export: step 2's
// bundle version, directory install count and revoke count (03-03), step
// 3's list and step 3's extraction. restoreSavedGrep finds any grep of it.
var (
	restoreSavedGreps = []string{
		`grep -o '"bundle_version":[0-9]*' /root/latest-saved.jsonl | tail -n 1`,
		`grep -c '"kind":"directory_install"' /root/latest-saved.jsonl`,
		`grep -c '"kind":"revoke"' /root/latest-saved.jsonl`,
		`grep -n -o '"kind":"\(bundle\|directory\)_install"' /root/latest-saved.jsonl`,
		`grep '"kind":"directory_install"' "$SAVED"`,
	}
	restoreSavedGrep = regexp.MustCompile(`grep (?:-[a-zA-Z]+ )*'[^']*' (?:/root/latest-saved\.jsonl|"\$SAVED")`)
	// restoreRestoredGreps are the runbook's greps of the restored export:
	// step 2's bundle version, directory install count and revoke count
	// (03-03). The revoke count was matched only by restoreRestoredGrep
	// until the pre-merge review of PR #61, so deleting it passed.
	restoreRestoredGreps = []string{
		`grep -o '"bundle_version":[0-9]*' /tmp/restored.jsonl | tail -n 1`,
		`grep -c '"kind":"directory_install"' /tmp/restored.jsonl`,
		restoreRestoredRevokeGrep,
	}
	restoreRestoredRevokeGrep = `grep -c '"kind":"revoke"' /tmp/restored.jsonl`
	// restoreRestoredGrep finds any grep of the restored export.
	restoreRestoredGrep = regexp.MustCompile(`grep (?:-[a-zA-Z]+ )*'[^']*' /tmp/restored\.jsonl`)
)

// TestRestoreRunbookChecks: signer-install.md still has every instruction
// of restoreRunbookChecks. The runbook and each check are compared with
// every line's leading and trailing space trimmed; a check of more than
// one line must be whole lines of the runbook. Step 2's verification of
// the saved export must also be unconditional on what the first command
// reports and come before every grep of the saved export (round 3), and
// the restored export must verify on its own before the first comparison
// and before every grep of it (round 4).
func TestRestoreRunbookChecks(t *testing.T) {
	trim := func(s string) string {
		l := strings.Split(s, "\n")
		for i := range l {
			l[i] = strings.TrimSpace(l[i])
		}
		return strings.Join(l, "\n")
	}
	raw := string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	requireReplayBlock(t, raw)
	runbook := "\n" + trim(raw) + "\n"
	for _, c := range restoreRunbookChecks {
		want := trim(c)
		if strings.Contains(want, "\n") {
			want = "\n" + want + "\n"
		}
		if !strings.Contains(runbook, want) {
			t.Errorf("signer-install.md no longer has %q, which TestRestoreReplaysLostDirectory carries out", c)
		}
	}
	for _, c := range restoreRecoveryChecks {
		want := trim(c)
		if strings.Contains(want, "\n") {
			want = "\n" + want + "\n"
		}
		if !strings.Contains(runbook, want) {
			t.Errorf("signer-install.md no longer has %q, which TestRestoreRecoversLostRevocations carries out", c)
		}
	}

	// The hold, file restore and release blocks, whole lines, in the
	// runbook and in the systemd-sandbox smoke test that runs them.
	// The copy-in and read-back blocks with their openers, which name the
	// admin as <admin> in the runbook and kradmin in smoke.sh (PR #70
	// review, F11).
	smoke := "\n" + trim(string(readFile(t, filepath.Join("..", "systemd", "smoke.sh")))) + "\n"
	for _, b := range []struct{ name, text, runbookOpener, smokeOpener string }{
		{"restore hold", restoreHoldBlock, "", ""},
		{"file restore", restoreFilesScript, "", ""},
		{"release of the restore hold", restoreReleaseBlock, "", ""},
		{"copy of the replay proposal to the admin", restoreAdminCopyScript, "", ""},
		{"capture of keyroster-server's KRL copy", restoreCaptureBlock, "", ""},
		{"copy of the recovery inputs to the admin", restoreCopyInScript, restoreAdminOpener, restoreSmokeAdminOpener},
		{"read-back of the recovery request", restoreReadBackScript, restoreAdminOpener, restoreSmokeAdminOpener},
		{"recovery line", restoreRecoverLine, "", ""},
		{"release check", restoreReleaseCheckBlock, "", ""},
		{"move of a refused request aside", restoreArchiveBlock, "", ""},
	} {
		if want := "\n" + trim(b.runbookOpener+b.text) + "\n"; !strings.Contains(runbook, want) {
			t.Errorf("signer-install.md no longer has the %s block:\n%s%s", b.name, b.runbookOpener, b.text)
		}
		if want := "\n" + trim(b.smokeOpener+b.text) + "\n"; !strings.Contains(smoke, want) {
			t.Errorf("test/systemd/smoke.sh no longer runs the runbook's %s block:\n%s%s", b.name, b.smokeOpener, b.text)
		}
	}

	// The cross-check block, whole lines; it runs in e2e only
	// (TestRestoreCrossCheck, TestAgentEnrollEndToEnd), not in smoke.sh.
	if want := "\n" + trim(restoreCrossCheckBlock) + "\n"; !strings.Contains(runbook, want) {
		t.Errorf("signer-install.md no longer has the cross-check block:\n%s", restoreCrossCheckBlock)
	}

	if strings.Contains(runbook, restoreRootInstall) {
		t.Errorf("signer-install.md has an admin run %q, which no admin account can read", restoreRootInstall)
	}
	for _, m := range restoreAdminPathWrite.FindAllString(runbook, -1) {
		t.Errorf("signer-install.md has root create, change or write an admin's path, following any link the admin planted: %q", strings.TrimSpace(m))
	}

	// The order, on the runbook's restore section with its white space
	// collapsed, so that a sentence may wrap anywhere.
	squash := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	section := runbook
	if i := strings.Index(section, "### A restore brings back the older trust bundle"); i >= 0 {
		section = section[i:]
	} else {
		t.Fatal("signer-install.md has no section \"A restore brings back the older trust bundle\"")
	}
	section = squash(section)
	if strings.Contains(section, squash(restoreShrankGate)) {
		t.Errorf("signer-install.md verifies the saved export only %q; a log reported as rewritten is then read unverified", restoreShrankGate)
	}
	pos := func(what, s string) int {
		i := strings.Index(section, squash(s))
		if i < 0 {
			t.Fatalf("signer-install.md has no %s: %q", what, s)
		}
		return i
	}
	restoredVerify := pos("audit verify of the restored export on its own", restoreRestoredVerify)
	restoredStop := pos("rule for a restored export that does not verify", restoreRestoredStop)
	first := pos("step 2 first command", restoreFirstCheck)
	if restoredVerify >= restoredStop || restoredStop >= first {
		t.Errorf("signer-install.md step 2 does not verify the restored export on its own first: its audit verify at %d, %q at %d, the first comparison at %d",
			restoredVerify, restoreRestoredStop, restoredStop, first)
	}
	if src := pos("rule for where the saved export comes from", restoreSavedSource); src <= restoredStop || src >= first {
		t.Errorf("signer-install.md step 2 does not say where the saved export comes from before the first comparison: %q at %d, the first comparison at %d",
			restoreSavedSource, src, first)
	}
	cond := pos("unconditional verification of the saved export", restoreSavedVerifyIf)
	block := pos("verification of the saved export", restoreSavedVerify)
	stop := pos("rule for a saved export that does not verify", restoreSavedStop)
	if first >= cond || cond >= block || block >= stop {
		t.Errorf("signer-install.md step 2 is out of order: first command at %d, %q at %d, the saved export's audit verify runs at %d, %q at %d",
			first, restoreSavedVerifyIf, cond, block, restoreSavedStop, stop)
	}
	// The hold comes before the file restore and before step 1, and is
	// released after step 2's checks and before step 3.
	hold := pos("restore hold", restoreHoldBlock)
	files := pos("file restore", restoreFilesScript)
	noBoot := pos("rule never to boot a VM snapshot", restoreVMNoBoot)
	ram := pos("rule for a VM snapshot with RAM", restoreVMRAM)
	step1 := pos("step 1", restoreStep1)
	release := pos("release of the restore hold", restoreReleaseBlock)
	step3 := pos("step 3", restoreStep3)
	if hold >= files || files >= step1 || files >= noBoot || noBoot >= step1 || ram >= step1 {
		t.Errorf("signer-install.md does not hold the units before the restore: hold at %d, file restore at %d, VM snapshot rule at %d, RAM rule at %d, step 1 at %d",
			hold, files, noBoot, ram, step1)
	}
	for _, c := range restoreVMBooted {
		if strings.Contains(section, c) {
			t.Errorf("signer-install.md still has %q: a VM snapshot is never booted (owner decision 2026-10-25, round 5)", c)
		}
	}
	if release <= stop || release >= step3 {
		t.Errorf("signer-install.md does not release the hold between step 2's checks and step 3: checks end at %d, release at %d, step 3 at %d",
			stop, release, step3)
	}
	// 03-06c: 03-03's stop and its interim text are gone, the saved-export
	// rule stays, and the recovery runs in this order: the capture after
	// the hold and before the file restore; the revoke counts after the
	// saved export is verified; then step 2b (the clock check, the copy,
	// the admin's command, the read-back, the recovery line, the recovered
	// export and its verifies), all before the release, which comes before
	// step 3.
	for _, gone := range []string{restoreRevokeStop, restoreRevokeInterim} {
		if strings.Contains(section, squash(gone)) {
			t.Errorf("signer-install.md still has 03-03's stop for a lost revocation (%q); step 2b recovers instead", gone)
		}
	}
	pos("operating rule for saved exports", restoreSavedExportRule)
	capture := pos("capture of keyroster-server's KRL copy", restoreCaptureBlock)
	if capture <= hold || capture >= files {
		t.Errorf("signer-install.md does not keep the server's KRL copy right after the hold and before the file restore: hold at %d, capture at %d, file restore at %d",
			hold, capture, files)
	}
	captureKept := pos("capture line for a kept copy", restoreCaptureKept)
	pos("capture line for no copy", restoreCaptureNone)
	if trust := pos("rule that the server copy is only as trustworthy as its account", restoreServerCopyTrust); trust <= captureKept || trust >= files {
		t.Errorf("signer-install.md does not say next to the capture block that the copy is only as trustworthy as the server account: capture line at %d, rule at %d, file restore at %d",
			captureKept, trust, files)
	}
	// 03-07 (T-03-277): the cross-check against the hosts comes after the
	// capture and before the file restore, and gates step 2b.
	crossNote := pos("pointer to the cross-check of the server copy", restoreServerCopyCheck)
	crossHead := pos("cross-check of the server copy against the hosts", restoreCrossCheckHead)
	crossCommand := strings.Index(section[crossHead:], squash(restoreCrossCheckCommand)) + crossHead
	crossLine := pos("pinned line of keyroster-agent krl-version", restoreCrossCheckLine)
	crossBlock := pos("cross-check block", restoreCrossCheckBlock)
	crossRule := pos("rule that only cross-check passed: lets step 2b run", restoreCrossCheckRule)
	pos("rule for a missing server copy in the cross-check", restoreCrossCheckNoCopy)
	residual := pos("residual of the cross-check", restoreCrossCheckResidual)
	withheld := pos("the withholding case of the cross-check's residual", restoreCrossCheckWithheld)
	escalate := pos("the unconditional escalation after a suspected server compromise", restoreCrossCheckEscalate)
	proves := pos("what a passing cross-check proves", restoreCrossCheckProves)
	if proves > crossBlock || residual > withheld || withheld > escalate {
		t.Error("signer-install.md: the cross-check's claim, its residual, the withholding case and the escalation are out of order")
	}
	crossGate := pos("step 2b's gate on the cross-check", restoreCrossCheckGate)
	adminRecover := pos("admin's keyroster revoke recover", restoreAdminRecover)
	if !(captureKept < crossNote && crossNote < crossHead && crossHead < crossCommand && crossCommand < crossLine && crossLine < crossBlock &&
		crossBlock < crossRule && crossRule < files && crossGate < adminRecover && crossRule < crossGate) {
		t.Errorf("signer-install.md's cross-check is out of order: capture line %d, pointer %d, head %d, command %d, line %d, block %d, rule %d, file restore %d, step 2b's gate %d, admin's recover %d",
			captureKept, crossNote, crossHead, crossCommand, crossLine, crossBlock, crossRule, files, crossGate, adminRecover)
	}
	krlRule := pos("rule that --krl is left out only after no server KRL copy", restoreKRLRule)
	releaseRule := pos("rule that nothing to recover after kept: keeps the hold", restoreReleaseRule)
	// posAfter finds s after from: the clock check's commands and rule also
	// stand in "Snapshot restore: check the clock first".
	posAfter := func(what, s string, from int) int {
		i := strings.Index(section[from:], squash(s))
		if i < 0 {
			t.Fatalf("signer-install.md has no %s after %d: %q", what, from, s)
		}
		return from + i
	}
	clock := pos("clock check of step 2b", restoreClockCheck)
	clockCommands := posAfter("clock check's commands", restoreClockCommands, clock)
	steps := []struct {
		what string
		at   int
	}{
		{"saved export's verify stop", stop},
		{"revoke count of the restored export", pos("revoke count of the restored export", restoreRestoredRevokeGrep)},
		{"clock check of step 2b", clock},
		{"clock check's commands", clockCommands},
		{"clock check's rule", posAfter("clock check's rule", restoreClockRule, clockCommands)},
		{"copy of the recovery inputs", pos("copy of the recovery inputs to the admin", restoreCopyInScript)},
		{"admin's keyroster revoke recover", pos("admin's keyroster revoke recover", restoreAdminRecover)},
		{"rule for --krl", krlRule},
		{"form of the server copy's import line", pos("form of the server copy's import line", restoreImportRule)},
		{"read-back of the request", pos("read-back of the recovery request", restoreReadBackScript)},
		{"recovery line", pos("recovery line", restoreRecoverLine)},
		{"export of the recovered log", pos("export of the recovered log", restoreRecoveryChecks[0])},
		{"verify of the recovered export", pos("verify of the recovered export", restoreRecoveryChecks[1]+"\n"+restoreRecoveryChecks[2])},
		{"release check", pos("release check", restoreReleaseCheckBlock)},
		{"rule for the release check's line", pos("rule for the release check's line", restoreReleaseCheckRule)},
		{"stop when the release check stops", pos("stop when the release check stops", restoreReleaseCheckStop)},
		{"rule that nothing to recover after kept: keeps the hold", releaseRule},
		{"remedy of recovery_evidence_invalid", pos("remedy of recovery_evidence_invalid", restoreOtherAdminRule)},
		{"move of a refused request aside", pos("move of a refused request aside", restoreArchiveBlock)},
		{"rule never to delete a refused request", pos("rule never to delete a refused request", restoreArchiveRule)},
		{"release condition after step 2b", pos("release condition after step 2b", restoreReleaseAfter2b)},
		{"first release case", pos("first release case", restoreReleaseCase1)},
		{"second release case", pos("second release case", restoreReleaseCase2)},
		{"release of the restore hold", release},
		{"release of a server on another host", pos("release of a server on another host", restoreRemoteRelease)},
		{"step 3", step3},
	}
	for i := 1; i < len(steps); i++ {
		if steps[i-1].at >= steps[i].at {
			t.Errorf("signer-install.md has the %s (at %d) before the %s (at %d); want step 2's checks, then step 2b in order, then the release and step 3",
				steps[i].what, steps[i].at, steps[i-1].what, steps[i-1].at)
		}
	}
	for _, g := range restoreSavedGreps {
		pos("grep of the saved export", g)
	}
	for _, g := range restoreRestoredGreps {
		pos("grep of the restored export", g)
	}
	greps := restoreSavedGrep.FindAllStringIndex(section, -1)
	if len(greps) < len(restoreSavedGreps) {
		t.Errorf("found %d greps of the saved export, want at least %d", len(greps), len(restoreSavedGreps))
	}
	for _, g := range greps {
		if g[0] < stop {
			t.Errorf("signer-install.md greps the saved export (%q) before it is verified", section[g[0]:g[1]])
		}
	}
	rgreps := restoreRestoredGrep.FindAllStringIndex(section, -1)
	if len(rgreps) < len(restoreRestoredGreps) {
		t.Errorf("found %d greps of the restored export, want at least %d (step 2's bundle version, directory install count and revoke count)", len(rgreps), len(restoreRestoredGreps))
	}
	for _, g := range rgreps {
		if g[0] < restoredStop {
			t.Errorf("signer-install.md greps the restored export (%q) before it is verified on its own", section[g[0]:g[1]])
		}
	}
}

// TestRestoreReplaysLostDirectory runs the signer restore procedure of
// signer-install.md step 3 on a test signer (03-02, D-20, review A-IN-01).
// Directory v1 (the first admin's approval) is installed; the signer is
// stopped and its signer.db copied; v2 (a role only, no passkey binding)
// is installed with keyroster directory install and the log exported. The
// signer is stopped, the copy restored and the signer started: it reports
// v1. The saved export verifies on its own and with the restored export
// as --previous; v2's directory.json and directory.json.sigs are written
// from it with the runbook's own commands and replayed with keyroster
// directory install: the signer reports v2 with the same bytes, and the
// new export verifies on its own and extends the restored export. It is
// no extension of the saved export (the replayed leaf is new), so audit
// verify --previous refuses it: the runbook says the post-replay export
// is the next baseline.
//
// A lost version that binds a passkey is not run here: the server refuses
// it with 409 credential_not_pending, and the runbook labels that case
// UNVERIFIED.
func TestRestoreReplaysLostDirectory(t *testing.T) {
	env := startServerEnv(t, serverOpts{StoppableSigner: true})
	stop := env.StopSigner
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	_, fp := enroll(t, env, admin, "admin1", webauthn.AlgEdDSA)
	if code, out, errOut := env.keyroster(t, admin, "", "user", "approve", "admin1", "--fingerprint", fp, "--yes"); code != 0 ||
		!strings.Contains(out, "The server reports directory version 1 installed") {
		t.Fatalf("user approve admin1: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if resp, _ := signerDirectory(t, env); resp.Version != 1 {
		t.Fatalf("signer directory version %d, want 1", resp.Version)
	}

	// 1. The backup: signer.db and whatever SQLite files belong to it,
	// taken from a stopped signer.
	stop()
	backup := t.TempDir()
	copyDB(t, env.Signer.StateDir, backup)
	stop = serveStoppable(t, env.Signer)

	// 2. v2 after the backup, through a proposal, as an admin would.
	work := t.TempDir()
	if code, out, errOut := env.keyroster(t, admin, work, "role", "add", "ops", "--max-ttl", "1h", "--out", "V2", "--yes"); code != 0 {
		t.Fatalf("role add ops --out V2: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if code, out, errOut := env.keyroster(t, admin, work, "directory", "install", "V2"); code != 0 ||
		!strings.Contains(out, "The server reports directory version 2 installed") {
		t.Fatalf("directory install V2: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	v2, _ := signerDirectory(t, env)
	if v2.Version != 2 {
		t.Fatalf("signer directory version %d, want 2", v2.Version)
	}
	saved := env.Signer.exportLog(t)
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, saved); code != 0 || !strings.Contains(out, "directory installs 2") {
		t.Fatalf("audit verify of the saved export: exit %d:\n%s", code, out)
	}

	// 3. The restore: the copy replaces signer.db, and the newer WAL files
	// go, or SQLite would replay them onto the old database.
	// The restored log is exported while the signer is stopped (step 1).
	stop()
	restoreDB(t, backup, env.Signer.StateDir)
	restored := env.Signer.exportLog(t)
	serveStoppable(t, env.Signer) // stopped at cleanup, as every daemon of the harness
	if resp, _ := signerDirectory(t, env); resp.Version != 1 {
		t.Fatalf("restored signer directory version %d, want 1", resp.Version)
	}
	// Step 2: the restored export verifies on its own, the saved export
	// verifies on its own pins (above), and the restored log is a prefix
	// of it.
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, restored); code != 0 || !strings.Contains(out, "directory installs 1") {
		t.Fatalf("audit verify of the restored export: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, saved, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <saved export>: exit %d:\n%s", code, out)
	}

	// 4. The proposal from the saved export, with the runbook's commands
	// (which must still be the runbook's).
	requireReplayBlock(t, string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md"))))
	replay := filepath.Join(t.TempDir(), "replay", "v2")
	cmd := exec.Command("bash", "-eu")
	cmd.Stdin = strings.NewReader(replayExtractScript)
	cmd.Env = append(os.Environ(), "V=2", "SAVED="+saved, "D="+replay)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "wrote the proposal of directory version 2") {
		t.Fatalf("the runbook's extraction failed: %v\n%s", err, out)
	}
	doc := readFile(t, filepath.Join(replay, "directory.json"))
	sigs := readFile(t, filepath.Join(replay, "directory.json.sigs"))
	if !bytes.Equal(doc, v2.Directory) || !bytes.Equal(sigs, v2.Sigs) {
		t.Fatal("the extracted proposal is not the directory and signatures the signer installed as v2")
	}
	// The same bytes as the verified leaf carries, not only the
	// unverified "decoded" part of the line.
	body := directoryInstallLeaf(t, saved, 2)
	if !bytes.Equal(doc, body.Directory) || !bytes.Equal(sigs, body.Sigs) {
		t.Fatal("the extracted proposal differs from the directory_install leaf of v2")
	}

	// The copy to the admin (step 3): the runbook writes the two files as
	// the admin into a new 0700 directory with mode 0600, because the
	// admin cannot read /root/replay. As the test's own user there is no
	// runuser (smoke.sh runs that block); the copy keeps the modes, and the
	// replay reads only it.
	adminCopy := filepath.Join(t.TempDir(), "replay", "v2")
	if err := os.MkdirAll(adminCopy, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"directory.json", "directory.json.sigs"} {
		if err := os.WriteFile(filepath.Join(adminCopy, name), readFile(t, filepath.Join(replay, name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 5. The replay. keyroster-server caches the signer's status for up
	// to 5 s (statusTTL); wait it out, so the CLI's base check reads the
	// restored v1 and not the v2 the server saw before the restore.
	time.Sleep(6 * time.Second)
	code, out, errOut := env.keyroster(t, admin, "", "directory", "install", adminCopy)
	if code != 0 || !strings.Contains(out, "The server reports directory version 2 installed") {
		t.Fatalf("directory install of the replayed v2: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	after, _ := signerDirectory(t, env)
	if after.Version != 2 || !bytes.Equal(after.Directory, v2.Directory) {
		t.Fatalf("signer directory after the replay: version %d, same bytes as v2: %v", after.Version, bytes.Equal(after.Directory, v2.Directory))
	}

	// 6. The new log verifies on its own and is the next baseline; it is
	// not an extension of the pre-restore export.
	replayed := env.Signer.exportLog(t)
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed); code != 0 || !strings.Contains(out, "directory installs 2") {
		t.Fatalf("audit verify after the replay: exit %d:\n%s", code, out)
	}
	// It extends the restored log, so nothing was cut back or rewritten
	// between the restore and the replay.
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <post-replay export>: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed, "--previous", saved); code == 0 {
		t.Fatalf("audit verify --previous <pre-restore export> accepted the post-replay export:\n%s", out)
	}
}

// copyDB copies signer.db and its -wal and -shm files, where present, from
// the state directory to dir.
func copyDB(t *testing.T, state, dir string) {
	t.Helper()
	n := 0
	for _, name := range []string{"signer.db", "signer.db-wal", "signer.db-shm"} {
		data, err := os.ReadFile(filepath.Join(state, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if _, err := os.Stat(filepath.Join(dir, "signer.db")); err != nil {
		t.Fatalf("no signer.db copied (%d files): %v", n, err)
	}
}

// restoreDB removes signer.db and its -wal and -shm files from the state
// directory and puts back the ones in dir.
func restoreDB(t *testing.T, dir, state string) {
	t.Helper()
	for _, name := range []string{"signer.db", "signer.db-wal", "signer.db-shm"} {
		if err := os.Remove(filepath.Join(state, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	copyDB(t, dir, state)
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// directoryInstallLeaf returns the body of the directory_install leaf of
// version v in export, decoded from the leaf bytes.
func directoryInstallLeaf(t *testing.T, export string, v uint64) *tlog.DirectoryInstallBody {
	t.Helper()
	f, err := os.Open(export) //nolint:gosec // G304: the test's export
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var l struct {
				Leaf string `json:"leaf"`
			}
			if err := json.Unmarshal(line, &l); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(l.Leaf)
			if err != nil {
				t.Fatal(err)
			}
			if leaf, err := tlog.DecodeLeaf(raw); err == nil && leaf.Kind == tlog.KindDirectoryInstall {
				b, err := tlog.DecodeDirectoryInstallBody(leaf.Body)
				if err != nil {
					t.Fatal(err)
				}
				if b.Version == v {
					return b
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("no directory_install leaf of version %d in %s", v, export)
	return nil
}
