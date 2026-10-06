// Package sshrunner implements agentless.Runner over SSH, keeping one
// long-lived connection per target and multiplexing sessions over it. Each run
// opens one session, executes batch.RemoteCommand and writes the script built
// by batch.Build to its standard input.
package sshrunner

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh"

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
	// Targets lists permitted destinations. Nil allows any target; a non-nil
	// empty slice allows none. Update retires connections removed from this
	// list. Addresses and auth selections use the same defaults as Run.
	Targets []agentless.Target

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
type Pool struct {
	mu           sync.Mutex
	cfg          *settings
	entries      map[agentless.Target]*connection
	notify       chan struct{}
	closed       bool
	dials        int
	hostFailures prometheus.Counter
	metrics      *poolMetrics
	logger       *slog.Logger
	stopReload   chan struct{}
	reloadDone   chan struct{}
}

// All mutable connection fields are guarded by Pool.mu. Network operations
// never hold that lock, including handshakes, session opens and keepalives.
type connection struct {
	client      *ssh.Client
	raw         net.Conn
	done        chan struct{}
	retired     bool
	dialing     bool
	active      int
	lastUse     time.Time
	retryAt     time.Time
	failures    int
	authFailure bool
}

var _ agentless.Runner = (*Pool)(nil)

// New returns a Pool for cfg. Pool metrics are registered with reg.
func New(cfg Config, logger *slog.Logger, reg prometheus.Registerer) (*Pool, error) {
	s, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p := &Pool{cfg: s, logger: logger, stopReload: make(chan struct{}), reloadDone: make(chan struct{}), entries: make(map[agentless.Target]*connection), notify: make(chan struct{}), hostFailures: prometheus.NewCounter(prometheus.CounterOpts{
		Name: "agentless_ssh_host_key_failures_total", Help: "SSH handshakes rejected by mandatory host key verification.",
	})}
	p.metrics = newPoolMetrics(p)
	if reg != nil {
		if err := reg.Register(p.metrics); err != nil {
			return nil, err
		}
	}
	// No credential or server-controlled handshake error is ever logged.
	go p.watchKnownHosts()
	return p, nil
}

// Update applies a new configuration. Connections whose target, credentials
// and known_hosts are unchanged stay open; others are closed.
func (p *Pool) Update(cfg Config) error {
	return p.update(cfg, prepare)
}

func (p *Pool) update(cfg Config, prepareConfig func(Config) (*settings, error)) error {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return errors.New("sshrunner: pool is closed")
		}
		previous := p.cfg
		p.mu.Unlock()

		s, err := prepareConfig(cfg)
		if err != nil {
			return err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return errors.New("sshrunner: pool is closed")
		}
		// A reload or another Update may have published newer trust while
		// these files were read. Re-read rather than resurrecting that older
		// snapshot. File I/O stays outside the connection-state lock.
		if p.cfg != previous {
			p.mu.Unlock()
			continue
		}
		for target, e := range p.entries {
			if _, ok := s.Auths[target.Auth]; !ok || !s.permits(target) || !sameIdentity(p.cfg, s, target.Auth) {
				p.retire(e)
				delete(p.entries, target)
			}
		}
		p.cfg = s
		p.signal()
		p.mu.Unlock()
		return nil
	}
}

const knownHostsReloadInterval = 30 * time.Second

func (p *Pool) watchKnownHosts() {
	defer close(p.reloadDone)
	ticker := time.NewTicker(knownHostsReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopReload:
			return
		case <-ticker.C:
			p.reloadKnownHosts()
		}
	}
}

func (p *Pool) reloadKnownHosts() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	previous := p.cfg
	p.mu.Unlock()

	contents, err := readKnownHosts(previous.KnownHostsFiles)
	var keys *hostKeys
	if err == nil {
		if sha256.Sum256(contents) == previous.trust {
			return
		}
		keys, err = parseKnownHosts(contents)
	}
	p.mu.Lock()
	// An Update, Close or another reload wins over this older read. Never
	// replace its credentials, membership or trust with a stale snapshot.
	if p.closed || p.cfg != previous {
		p.mu.Unlock()
		return
	}
	if err != nil {
		p.metrics.reloadFailures.Inc()
		p.mu.Unlock()
		// Parser errors can contain attacker-controlled file contents. Log only
		// a fixed diagnostic, with no path, target or credential information.
		p.logger.Error("sshrunner: known_hosts reload failed; retaining previous snapshot")
		return
	}
	next := *previous
	next.hostKeys = keys
	for target, e := range p.entries {
		p.retire(e)
		delete(p.entries, target)
	}
	p.cfg = &next
	p.signal()
	p.mu.Unlock()
}

// Run implements agentless.Runner.
func (p *Pool) Run(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("sshrunner: pool is closed")
	}
	cfg := p.cfg
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	nonce, err := batch.NewNonce()
	if err != nil {
		return nil, err
	}
	script, err := batch.Build(reads, nonce)
	if err != nil {
		return nil, err
	}
	target, err = normalizeTarget(target)
	if err != nil {
		return nil, err
	}
	e, client, raw, err := p.acquire(ctx, target)
	if err != nil {
		return nil, err
	}
	release := func() {
		p.mu.Lock()
		e.active--
		p.metrics.sessions.Dec()
		e.lastUse = time.Now()
		p.signal()
		p.mu.Unlock()
	}

	// Channel open and exec requests can hang too. Cancellation during setup
	// tears down the transport; after setup it closes only this session.
	stopSetup := context.AfterFunc(ctx, func() { _ = raw.Close() })
	session, err := client.NewSession()
	if err != nil {
		stopSetup()
		release()
		return nil, errors.New("sshrunner: cannot open session")
	}
	reader, writer := io.Pipe()
	session.Stdin = strings.NewReader(script)
	session.Stdout = writer
	session.Stderr = io.Discard
	defer reader.Close()
	waitDone := make(chan struct{})
	defer closeSession(session, raw, cfg.KeepaliveTimeout, waitDone, release)
	if err = session.Start(batch.RemoteCommand); err != nil {
		stopSetup()
		_ = writer.CloseWithError(err)
		p.broken(e, client, raw)
		close(waitDone)
		return nil, errors.New("sshrunner: cannot start fixed batch command")
	}
	go func() {
		_ = writer.CloseWithError(session.Wait())
		close(waitDone)
	}()
	if !stopSetup() && ctx.Err() != nil {
		_ = writer.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	return batch.Demux(ctx, reader, nonce, reads, cfg.Limits)
}

// Close closes every connection. Run fails after Close.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.stopReload)
		for target, e := range p.entries {
			p.retire(e)
			delete(p.entries, target)
		}
		p.signal()
	}
	return nil
}

func (p *Pool) signal() { close(p.notify); p.notify = make(chan struct{}) }

// retire also cancels a handshake which has not yet produced a client.
func (p *Pool) retire(e *connection) {
	if !e.retired {
		e.retired = true
		close(e.done)
	}
	if e.raw != nil {
		_ = e.raw.Close()
		e.raw = nil
		e.client = nil
	}
}
