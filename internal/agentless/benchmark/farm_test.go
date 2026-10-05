//go:build sshscale && (darwin || linux)

package benchmark

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"
	"golang.org/x/crypto/ssh"

	"github.com/grafana/alloy/internal/agentless/batch"
)

// blackholeConn discards bytes on an established stream without FIN/RST.
// Only connections existing at injection are affected; new dials can recover.
// This emulates an application-visible half-open path, not kernel packet loss.
type blackholeConn struct {
	net.Conn
	drop atomic.Bool
}

func (c *blackholeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if !c.drop.Load() || err != nil {
			return n, err
		}
	}
}

func (c *blackholeConn) Write(p []byte) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

type targetServer struct {
	mu         sync.Mutex
	listener   net.Listener
	acceptDone chan struct{}
	address    string
	host       ssh.Signer
	password   string
	deny       bool
	conns      map[*blackholeConn]bool
	wg         sync.WaitGroup
	auths      atomic.Int64
	rejects    atomic.Int64
	accepts    atomic.Int64
}

func newSigner() (ssh.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func newTarget(host ssh.Signer) (*targetServer, error) {
	s := &targetServer{host: host, password: "local-benchmark", conns: make(map[*blackholeConn]bool)}
	if err := s.start("127.0.0.1:0"); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *targetServer) start(address string) error {
	l, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener, s.address = l, l.Addr().String()
	s.acceptDone = make(chan struct{})
	done := s.acceptDone
	s.mu.Unlock()
	go func() {
		defer close(done)
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			c := &blackholeConn{Conn: raw}
			s.mu.Lock()
			s.conns[c] = true
			host := s.host
			s.mu.Unlock()
			s.accepts.Inc()
			s.wg.Add(1)
			go s.connection(c, host)
		}
	}()
	return nil
}

func (s *targetServer) connection(c *blackholeConn, host ssh.Signer) {
	defer s.wg.Done()
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		s.auths.Inc()
		s.mu.Lock()
		allowed := !s.deny && meta.User() == "reader" && string(pass) == s.password
		s.mu.Unlock()
		if !allowed {
			s.rejects.Inc()
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(host)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer conn.Close()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ssh.DiscardRequests(requests)
	}()
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, reqs, err := ch.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer channel.Close()
			for r := range reqs {
				var payload struct{ Command string }
				if r.Type != "exec" || ssh.Unmarshal(r.Payload, &payload) != nil || payload.Command != batch.RemoteCommand {
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(true, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				stopRead := context.AfterFunc(ctx, func() { _ = channel.Close() })
				script, readErr := io.ReadAll(io.LimitReader(channel, 8193))
				stopRead()
				if readErr != nil || !allowedScript(script) {
					cancel()
					return
				}
				cmd := exec.CommandContext(ctx, "sh", "-s")
				cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(string(script)), channel, io.Discard
				cmd.WaitDelay = 100 * time.Millisecond
				err := cmd.Run()
				cancel()
				status := uint32(0)
				if err != nil {
					status = 1
				}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				return
			}
		}()
	}
}

func (s *targetServer) disconnect(blackhole bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		if blackhole {
			c.drop.Store(true)
		} else {
			_ = c.Close()
		}
	}
	return len(s.conns)
}

// stop waits for the accept loop before waiting on connection handlers. Only
// sockets actually created by this target and bounded sh children are closed.
func (s *targetServer) stop() {
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	_ = l.Close()
	<-s.acceptDone
	s.disconnect(false)
	s.wg.Wait()
}

var noncePattern = regexp.MustCompile(`([a-f0-9]{32}):0:begin`)

// Do not expose a general-purpose shell even to other loopback users. Admit
// only the exact batch compiled into this harness; stdin and child lifetimes
// are bounded independently of whether the local SSH client is cooperative.
func allowedScript(script []byte) bool {
	matches := noncePattern.FindSubmatch(script)
	if len(matches) != 2 || len(script) > 8192 {
		return false
	}
	expected, err := batch.Build(scaleReads, string(matches[1]))
	return err == nil && string(script) == expected
}

func startFarm(n int) ([]*targetServer, error) {
	farm := make([]*targetServer, 0, n)
	for range n {
		host, err := newSigner()
		if err != nil {
			stopFarm(farm)
			return nil, err
		}
		s, err := newTarget(host)
		if err != nil {
			stopFarm(farm)
			return nil, fmt.Errorf("farm capacity at %d targets: %w", len(farm), err)
		}
		farm = append(farm, s)
	}
	return farm, nil
}

func stopFarm(farm []*targetServer) {
	for _, s := range farm {
		s.stop()
	}
}
