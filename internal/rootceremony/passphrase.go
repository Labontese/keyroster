package rootceremony

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"unicode/utf8"

	"golang.org/x/term"
)

// minPassphraseRunes is the shortest passphrase a software root accepts.
const minPassphraseRunes = 20

// maxPassphraseBytes bounds a passphrase line read from a file descriptor.
const maxPassphraseBytes = 1024

// ReadPassphrase reads a root passphrase. With fd >= 0 it reads one line
// from that inherited file descriptor (the line ending is dropped, the
// descriptor is left open for its owner). Otherwise stdin must be a
// terminal: the prompt goes to stderr, the input is not echoed, and with
// confirm the passphrase is asked twice and must match. Passphrases are
// never taken from command-line arguments or environment variables
// (T-01-44).
func ReadPassphrase(fd int, prompt string, confirm bool) ([]byte, error) {
	if fd >= 0 {
		return readPassphraseFD(fd)
	}
	stdin := int(os.Stdin.Fd()) //nolint:gosec // G115: a file descriptor or Windows handle fits in int
	if !term.IsTerminal(stdin) {
		return nil, errors.New("rootceremony: stdin is not a terminal; type the passphrase on a terminal or pass it on an inherited descriptor with --passphrase-fd")
	}
	first, err := promptPassphrase(stdin, prompt)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return first, nil
	}
	second, err := promptPassphrase(stdin, "Repeat the passphrase: ")
	defer clear(second)
	if err != nil {
		clear(first)
		return nil, err
	}
	if !bytes.Equal(first, second) {
		clear(first)
		return nil, errors.New("rootceremony: the passphrases do not match")
	}
	return first, nil
}

func promptPassphrase(stdin int, prompt string) ([]byte, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(stdin)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(p)
		return nil, fmt.Errorf("rootceremony: read passphrase: %w", err)
	}
	if len(p) == 0 {
		return nil, errors.New("rootceremony: empty passphrase")
	}
	return p, nil
}

// readPassphraseFD reads up to the first newline from fd, one byte at a
// time so nothing past the line is consumed.
func readPassphraseFD(fd int) ([]byte, error) {
	buf := make([]byte, 0, 128)
	var b [1]byte
	for {
		n, err := readFD(fd, b[:])
		if err != nil {
			clear(buf)
			return nil, fmt.Errorf("rootceremony: read passphrase from descriptor %d: %w", fd, err)
		}
		if n == 0 || b[0] == '\n' {
			break
		}
		if len(buf) == maxPassphraseBytes {
			clear(buf)
			return nil, fmt.Errorf("rootceremony: passphrase on descriptor %d is longer than %d bytes", fd, maxPassphraseBytes)
		}
		buf = append(buf, b[0])
	}
	b[0] = 0
	buf = bytes.TrimSuffix(buf, []byte("\r"))
	if len(buf) == 0 {
		return nil, fmt.Errorf("rootceremony: empty passphrase on descriptor %d", fd)
	}
	return buf, nil
}

// ValidatePassphrase refuses passphrases shorter than 20 characters
// (Unicode code points) and passphrases that are not valid UTF-8.
func ValidatePassphrase(p []byte) error {
	if !utf8.Valid(p) {
		return errors.New("rootceremony: the passphrase is not valid UTF-8")
	}
	if n := utf8.RuneCount(p); n < minPassphraseRunes {
		return fmt.Errorf("rootceremony: the passphrase has %d characters; a root passphrase needs at least %d", n, minPassphraseRunes)
	}
	return nil
}
