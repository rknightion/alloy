// Package sshrunner implements agentless.Runner over SSH, keeping one
// long-lived connection per target and multiplexing sessions over it. Each run
// opens one session, executes batch.RemoteCommand and writes the script built
// by batch.Build to its standard input.
package sshrunner

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/batch"
)

// DefaultPort is used when a target address has no port.
const DefaultPort = "22"

// DefaultAuthName names the credentials used by targets that do not select
// any.
const DefaultAuthName = "default"

// Auth holds one set of SSH credentials. At least one of PrivateKey and
// Password must be set. Secret fields are never logged.
type Auth struct {
	Username string
	// PrivateKey is a PEM or OpenSSH private key.
	PrivateKey []byte
	// Passphrase decrypts PrivateKey when it is encrypted.
	Passphrase []byte
	Password   []byte
}

// Config configures a Pool. A zero field takes the value from DefaultConfig.
type Config struct {
	// Auths maps an auth name to credentials. Targets select one by
	// agentless.Target.Auth; an empty selection uses DefaultAuthName.
	Auths map[string]Auth
	// KnownHostsFiles lists OpenSSH known_hosts files. At least one is
	// required. @cert-authority lines are honoured. There is no option to
	// skip host key verification. The client's HostKeyAlgorithms must be
	// derived from the known_hosts entries for the target (golang/go#29286),
	// or a host with several key types fails verification.
	KnownHostsFiles []string

	// DialTimeout bounds TCP connect plus the SSH handshake.
	DialTimeout time.Duration
	// Timeout bounds one batch run when the caller's context has no earlier
	// deadline. When the deadline passes, Run returns the completed reads,
	// closes the session and frees its slot.
	Timeout time.Duration
	// MaxSessionsPerTarget caps concurrent sessions on one connection. It
	// must stay below the OpenSSH MaxSessions default of 10.
	MaxSessionsPerTarget int
	// KeepaliveInterval is how often an idle connection is probed.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout is how long a probe may go unanswered before the
	// connection is closed as half-open.
	KeepaliveTimeout time.Duration
	// IdleTimeout closes a connection no scrape has used for this long, so a
	// target that moved to another cluster peer releases its connection.
	IdleTimeout time.Duration
	// ReconnectBackoffMin and ReconnectBackoffMax bound the jittered
	// exponential backoff between failed dials to one target.
	ReconnectBackoffMin time.Duration
	ReconnectBackoffMax time.Duration
	// AuthFailureBackoffMin and AuthFailureBackoffMax bound the backoff
	// after an authentication failure, so retries never flood the target's
	// auth log or lock the account.
	AuthFailureBackoffMin time.Duration
	AuthFailureBackoffMax time.Duration
	// MaxConcurrentDials caps dials in flight across all targets, so a
	// restart does not open a connection storm.
	MaxConcurrentDials int
	// Limits bounds batch output.
	Limits batch.Limits
}

// DefaultConfig holds the default value of every tunable.
var DefaultConfig = Config{
	DialTimeout:           5 * time.Second,
	Timeout:               10 * time.Second,
	MaxSessionsPerTarget:  2,
	KeepaliveInterval:     15 * time.Second,
	KeepaliveTimeout:      5 * time.Second,
	IdleTimeout:           5 * time.Minute,
	ReconnectBackoffMin:   1 * time.Second,
	ReconnectBackoffMax:   2 * time.Minute,
	AuthFailureBackoffMin: 1 * time.Minute,
	AuthFailureBackoffMax: 30 * time.Minute,
	MaxConcurrentDials:    16,
	Limits:                batch.DefaultLimits,
}

// ErrAuthBackoff is returned by Run while a target is backing off after an
// authentication failure.
var ErrAuthBackoff = errors.New("sshrunner: target is backing off after an authentication failure")

// Pool is an agentless.Runner holding one SSH connection per target.
type Pool struct{}

var _ agentless.Runner = (*Pool)(nil)

// New returns a Pool for cfg. Pool metrics are registered with reg.
func New(cfg Config, logger *slog.Logger, reg prometheus.Registerer) (*Pool, error) {
	return nil, agentless.ErrNotImplemented
}

// Update applies a new configuration. Connections whose target, credentials
// and known_hosts are unchanged stay open; others are closed.
func (p *Pool) Update(cfg Config) error {
	return agentless.ErrNotImplemented
}

// Run implements agentless.Runner.
func (p *Pool) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	return nil, agentless.ErrNotImplemented
}

// Close closes every connection. Run fails after Close.
func (p *Pool) Close() error {
	return agentless.ErrNotImplemented
}
