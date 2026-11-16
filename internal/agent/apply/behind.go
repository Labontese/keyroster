//go:build linux

package apply

import (
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/state"
)

// bundleBehind is the heartbeat's bundle_behind for the accepted state st
// at now (03-12c), nil while the host is not behind or within the grace.
func (e *engine) bundleBehind(_ *state.Stored, _ time.Time, _ bool) *heartbeat.BundleBehind {
	return nil
}
