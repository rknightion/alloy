// Package batch builds the single POSIX sh script that runs every read of a
// scrape in one remote exec, and splits that script's output back into one
// result per read.
//
// The script is built only from validated, compiled-in reads (see
// agentless.Read.Validate); no configuration or target value is ever placed in
// it, and neither is a Read.ID: sections are numbered by their position.
// Sections are framed by delimiter lines carrying a per-run random nonce, so
// output that imitates a delimiter cannot shift section boundaries.
//
// A runner delivers the script on the standard input of the fixed remote
// command "sh -s", never in argv. That keeps the nonce out of /proc/*/cmdline,
// where other users on the target could read it, and works whatever the remote
// user's login shell is. Standard error of each read is discarded.
package batch

import (
	"context"
	"io"

	"github.com/grafana/alloy/internal/agentless"
)

// Limits bounds the output a batch may produce.
type Limits struct {
	// MaxSectionBytes caps the output kept for one read. Output beyond the
	// cap is discarded and the Result is marked Truncated.
	MaxSectionBytes int
	// MaxOutputBytes caps the total output read from the target. Exceeding
	// it fails the whole batch.
	MaxOutputBytes int
}

// DefaultLimits are the limits used when a caller does not set its own.
var DefaultLimits = Limits{
	MaxSectionBytes: 1 << 20, // 1 MiB
	MaxOutputBytes:  8 << 20, // 8 MiB
}

// RemoteCommand is the fixed command a runner executes; the script goes to its
// standard input.
const RemoteCommand = "sh -s"

// NewNonce returns a fresh random nonce for one batch run: 32 lowercase hex
// characters from crypto/rand.
func NewNonce() (string, error) {
	return "", agentless.ErrNotImplemented
}

// Build returns the sh script that runs reads in order under nonce. It
// returns an error when any read fails agentless.Read.Validate or the nonce is
// malformed.
func Build(reads []agentless.Read, nonce string) (string, error) {
	return "", agentless.ErrNotImplemented
}

// Demux reads the output of a script built by Build with the same reads and
// nonce, and returns one Result per read, in order, setting ExitStatus,
// NotExist and Truncated from the framing. When ctx ends or r fails mid-batch,
// it returns the completed sections and marks the rest TimedOut. It returns an
// error when the framing is malformed, the output exceeds
// limits.MaxOutputBytes, or nothing arrived before ctx ended.
func Demux(ctx context.Context, r io.Reader, nonce string, reads []agentless.Read, limits Limits) ([]agentless.Result, error) {
	return nil, agentless.ErrNotImplemented
}
