//go:build linux

package apply

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// The minimal probe account check (03-10b; 03-10c extends it here with the
// shadow file, sshd -T -C and the Allow and Deny rules, and 03-14 mirrors
// this file). Its reasons are gate hold reasons (Contracts frozen by
// 03-10b).
const (
	accountMissing    = "account_missing"
	accountUnparsable = "account_unparsable"
	accountUIDZero    = "account_uid_zero"
	shellMissing      = "shell_missing"
	shellNotNologin   = "shell_not_nologin"
)

// maxPasswd bounds <root>/etc/passwd: a larger file is account_unparsable.
const maxPasswd = 1 << 20

// parsePasswdLine splits one passwd(5) line into its seven fields and
// requires a decimal uid; ok is false for anything else.
func parsePasswdLine(line string) ([]string, bool) {
	f := strings.Split(line, ":")
	if len(f) != 7 || f[0] == "" {
		return nil, false
	}
	if _, err := strconv.ParseUint(f[2], 10, 32); err != nil {
		return nil, false
	}
	return f, true
}

// checkProbeAccount is the minimal check of the probe account on the host
// at root: <root>/etc/passwd has exactly one line for account, which
// parses (seven fields, a decimal uid), whose uid is not 0 and whose shell
// is an absolute path naming an existing executable regular file under
// root (links followed) called nologin. It returns "" or the first failing
// reason, and the account's passwd line (for the failure key). Lines of
// other accounts are ignored, malformed or not: a NIS entry must not hold
// every addition.
func checkProbeAccount(root, account string) (reason, line string) {
	f, err := os.Open(filepath.Join(root, "etc", "passwd")) //nolint:gosec // the host's own passwd file under the layout root
	if errors.Is(err, fs.ErrNotExist) {
		return accountMissing, ""
	}
	if err != nil {
		return accountUnparsable, ""
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxPasswd+1))
	if err != nil || len(b) > maxPasswd {
		return accountUnparsable, ""
	}
	var own []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxPasswd+1)
	for sc.Scan() {
		l := sc.Text()
		if name, _, _ := strings.Cut(l, ":"); name == account {
			own = append(own, l)
		}
	}
	if sc.Err() != nil {
		return accountUnparsable, ""
	}
	switch len(own) {
	case 0:
		return accountMissing, ""
	case 1:
	default:
		return accountUnparsable, own[0]
	}
	line = own[0]
	fields, ok := parsePasswdLine(line)
	if !ok {
		return accountUnparsable, line
	}
	if uid, _ := strconv.ParseUint(fields[2], 10, 32); uid == 0 {
		return accountUIDZero, line
	}
	shell := fields[6]
	if !path.IsAbs(shell) {
		return accountUnparsable, line
	}
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(shell)))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return shellMissing, line
	}
	if path.Base(shell) != "nologin" {
		return shellNotNologin, line
	}
	return "", line
}
