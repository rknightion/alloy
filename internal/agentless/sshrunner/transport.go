package sshrunner

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/grafana/alloy/internal/agentless"
)

func normalizeTarget(t agentless.Target) (agentless.Target, error) {
	if t.Address == "" {
		return t, errors.New("sshrunner: empty target address")
	}
	if _, _, err := net.SplitHostPort(t.Address); err != nil {
		host := strings.TrimPrefix(strings.TrimSuffix(t.Address, "]"), "[")
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return t, errors.New("sshrunner: invalid target address")
		}
		t.Address = net.JoinHostPort(host, DefaultPort)
	}
	if t.Auth == "" {
		t.Auth = DefaultAuthName
	}
	return t, nil
}

// Jitter never shortens the minimum quiet period for authentication failures.
// Saturation avoids duration overflow. The result always stays inside [min,max].
func backoff(minimum, maximum time.Duration, failures int) time.Duration {
	upper := minimum
	for i := 0; i < failures && upper < maximum; i++ {
		if upper > maximum/2 {
			upper = maximum
		} else {
			upper *= 2
		}
	}
	if upper <= minimum {
		return minimum
	}
	return minimum + time.Duration(rand.Int64N(int64(upper-minimum)))
}

func (p *Pool) failure(e *connection, auth bool) {
	e.failures++
	e.authFailure = auth
	minimum, maximum := p.cfg.ReconnectBackoffMin, p.cfg.ReconnectBackoffMax
	if auth {
		minimum, maximum = p.cfg.AuthFailureBackoffMin, p.cfg.AuthFailureBackoffMax
	}
	e.retryAt = time.Now().Add(backoff(minimum, maximum, e.failures))
}

func (p *Pool) acquire(ctx context.Context, target agentless.Target) (*connection, *ssh.Client, net.Conn, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, nil, nil, errors.New("sshrunner: pool is closed")
		}
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, nil, nil, err
		}
		cfg := p.cfg
		if _, ok := cfg.Auths[target.Auth]; !ok {
			p.mu.Unlock()
			return nil, nil, nil, errors.New("sshrunner: unknown auth selection")
		}
		e := p.entries[target]
		if e == nil {
			e = &connection{done: make(chan struct{}), lastUse: time.Now()}
			p.entries[target] = e
		}
		if time.Now().Before(e.retryAt) {
			auth := e.authFailure
			p.mu.Unlock()
			if auth {
				return nil, nil, nil, ErrAuthBackoff
			}
			return nil, nil, nil, errors.New("sshrunner: target is backing off after a transport failure")
		}
		if e.client != nil && e.active < cfg.MaxSessionsPerTarget {
			e.active++
			p.metrics.sessions.Inc()
			e.lastUse = time.Now()
			client, raw := e.client, e.raw
			p.mu.Unlock()
			return e, client, raw, nil
		}
		if e.client == nil && !e.dialing && p.dials < cfg.MaxConcurrentDials {
			e.dialing = true
			p.dials++
			p.mu.Unlock()
			client, raw, auth, err := p.dial(ctx, target, e, cfg)
			p.mu.Lock()
			e.dialing = false
			p.dials--
			if e.retired || p.closed {
				if raw != nil {
					_ = raw.Close()
				}
				err = errors.New("sshrunner: connection configuration was retired")
			} else if err != nil {
				// A caller abandoning a scrape is not a target failure.
				if contextLive(ctx) {
					p.failure(e, auth)
				}
			} else {
				e.client, e.raw = client, raw
				e.retryAt = time.Time{}
				e.failures = 0
				e.authFailure = false
				go p.monitor(e, client, raw)
			}
			p.signal()
			p.mu.Unlock()
			if err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		notify := p.notify
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-notify:
		}
	}
}

// A socket deadline can fire before the context timer's callback is scheduled.
// Check the deadline too, so that race cannot misclassify an expired handshake.
func contextLive(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}

func (p *Pool) dial(ctx context.Context, target agentless.Target, e *connection, cfg *settings) (*ssh.Client, net.Conn, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	p.metrics.dials.Inc()
	reason := "other"
	defer func() {
		if reason != "" {
			p.metrics.errors.WithLabelValues(reason).Inc()
		}
	}()
	// Update/Close must cancel a dial even before TCP is connected.
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	algorithms := cfg.algorithms(target.Address)
	if len(algorithms) == 0 {
		reason = "host_key"
		p.hostFailures.Inc()
		return nil, nil, false, errors.New("sshrunner: no trusted host key algorithms for target")
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Address)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			reason = "refused"
		} else if errors.Is(err, context.DeadlineExceeded) || (!contextLive(ctx) && ctx.Err() != context.Canceled) {
			reason = "timeout"
		}
		return nil, nil, false, errors.New("sshrunner: TCP connection failed")
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	var hostErr error
	hostVerified := false
	clientConfig := &ssh.ClientConfig{
		User: cfg.Auths[target.Auth].Username, Auth: cfg.methods[target.Auth], HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			hostErr = cfg.verify(host, remote, key)
			if hostErr != nil {
				p.hostFailures.Inc()
			} else {
				hostVerified = true
			}
			return hostErr
		},
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, target.Address, clientConfig)
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		_ = raw.Close()
		if hostErr != nil {
			reason = "host_key"
			return nil, nil, false, errors.New("sshrunner: host key verification failed: " + hostErr.Error())
		}
		var negotiation *ssh.AlgorithmNegotiationError
		if errors.As(err, &negotiation) && negotiation.What == "host key" {
			reason = "host_key"
			p.hostFailures.Inc()
			return nil, nil, false, errors.New("sshrunner: host key algorithms do not match known_hosts")
		}
		// x/crypto has no exported authentication error type. Conservatively
		// back off failed handshakes after verification while the dial context
		// is live, including servers that disconnect rather than rejecting
		// authentication. A dial timeout is a transport failure, not evidence
		// of bad credentials. Do not expose server-controlled error strings.
		auth := err != nil && hostVerified && contextLive(ctx)
		if auth {
			reason = "auth"
			return nil, nil, true, errors.New("sshrunner: authentication failed")
		}
		if !contextLive(ctx) && ctx.Err() != context.Canceled {
			reason = "timeout"
		}
		return nil, nil, false, errors.New("sshrunner: SSH handshake failed")
	}
	_ = raw.SetDeadline(time.Time{})
	reason = ""
	return ssh.NewClient(conn, channels, requests), raw, false, nil
}

func (p *Pool) broken(e *connection, client *ssh.Client, raw net.Conn) {
	_ = raw.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.client == client {
		e.client = nil
		e.raw = nil
		p.failure(e, false)
		p.signal()
	}
}

func (p *Pool) monitor(e *connection, client *ssh.Client, raw net.Conn) {
	disconnected := make(chan struct{})
	go func() { _ = client.Wait(); close(disconnected) }()
	for {
		p.mu.Lock()
		cfg := p.cfg
		interval := min(cfg.KeepaliveInterval, cfg.IdleTimeout)
		current := e.client == client && !e.retired && !p.closed
		p.mu.Unlock()
		if !current {
			return
		}
		timer := time.NewTimer(interval)
		select {
		case <-e.done:
			timer.Stop()
			return
		case <-disconnected:
			timer.Stop()
			p.broken(e, client, raw)
			return
		case <-timer.C:
		}
		p.mu.Lock()
		idle := e.client == client && e.active == 0 && time.Since(e.lastUse) >= p.cfg.IdleTimeout
		if idle {
			// Detach under the same lock as slot acquisition. Otherwise a
			// scrape could acquire this connection after the idle check and
			// have its active session closed by cleanup.
			e.client = nil
			e.raw = nil
			p.signal()
		}
		p.mu.Unlock()
		if idle {
			_ = raw.Close()
			return
		}
		response := make(chan struct{})
		go func() { _, _, _ = client.SendRequest("keepalive@openssh.com", true, nil); close(response) }()
		timer.Reset(cfg.KeepaliveTimeout)
		select {
		case <-e.done:
			timer.Stop()
			return
		case <-disconnected:
			timer.Stop()
			p.broken(e, client, raw)
			return
		case <-timer.C:
			p.broken(e, client, raw)
			return
		case <-response:
			timer.Stop()
		}
	}
}

// A close packet must not hang on a half-open TCP stream. The fallback closes
// that transport to unblock all SSH goroutines; normal cancellation is scoped
// to the session and leaves multiplexed peers and the connection intact.
func closeSession(session *ssh.Session, raw net.Conn, timeout time.Duration, waitDone <-chan struct{}, release func()) {
	var once sync.Once
	closed := make(chan struct{})
	go func() {
		_ = session.Close()
		// Enqueue channel-close before making the slot available, so a new
		// channel-open cannot overtake it on this multiplexed transport.
		once.Do(release)
		close(closed)
	}()
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		// Both the close write and the peer's channel shutdown must complete.
		// A peer ignoring channel-close must not retain Wait/copy goroutines.
		for closed != nil || waitDone != nil {
			select {
			case <-closed:
				closed = nil
			case <-waitDone:
				waitDone = nil
			case <-timer.C:
				_ = raw.Close()
				once.Do(release)
				return
			}
		}
	}()
}
