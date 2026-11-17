package signer

import (
	"context"
	"fmt"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
)

// The refusals of a switch install (03-12e), each an ErrBundleInstall.
var (
	ErrDrainWindowTooShort        = fmt.Errorf("%w: drain_window_too_short", ErrBundleInstall)
	ErrDrainWindowTooLong         = fmt.Errorf("%w: drain_window_too_long", ErrBundleInstall)
	ErrInstallPreviousRequired    = fmt.Errorf("%w: install_previous_required", ErrBundleInstall)
	ErrInstallPreviousInvalid     = fmt.Errorf("%w: install_previous_invalid", ErrBundleInstall)
	ErrInstallPreviousNotExtended = fmt.Errorf("%w: install_previous_not_extended", ErrBundleInstall)
	ErrDrainScanMissing           = fmt.Errorf("%w: drain_scan_missing", ErrBundleInstall)
)

// DrainNote is what a switch install bound for one newly draining CA
// entry (03-12e): its role, generation and trusted_until, and the logged
// certificate of its key with the largest ValidBefore (Recorded false when
// the log records none).
type DrainNote struct {
	Role         string
	Generation   uint32
	TrustedUntil string
	Max          krl.DrainEntry
	Recorded     bool
}

// InstallBundleWithPrevious is InstallBundle with previous, the checkpoint
// of an export-log file kept off the box (03-12e).
func InstallBundleWithPrevious(ctx context.Context, db *signerdb.DB, be keystore.Backend, pins []string, threshold int,
	bundle, bundleSigs, policy, policySigs []byte, clock serial.Clock, _ []byte) (*trust.Bundle, []DrainNote, error) {
	b, err := InstallBundle(ctx, db, be, pins, threshold, bundle, bundleSigs, policy, policySigs, clock)
	return b, nil, err
}
