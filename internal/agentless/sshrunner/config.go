package sshrunner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/grafana/alloy/internal/agentless"
)

type settings struct {
	Config
	methods map[string][]ssh.AuthMethod
	targets map[agentless.Target]struct{}
	*hostKeys
}

type hostKeys struct {
	trust     [32]byte
	verify    ssh.HostKeyCallback
	certLines map[int]bool
}

func prepare(cfg Config) (*settings, error) {
	// Take ownership of the secrets; mutations by the caller cannot change an
	// established connection's identity or bypass Update's comparison.
	auths := make(map[string]Auth, len(cfg.Auths))
	methods := make(map[string][]ssh.AuthMethod, len(cfg.Auths))
	for name, auth := range cfg.Auths {
		if auth.Username == "" || (len(auth.PrivateKey) == 0 && len(auth.Password) == 0) {
			return nil, errors.New("sshrunner: each auth requires a username and credentials")
		}
		auth.PrivateKey = bytes.Clone(auth.PrivateKey)
		auth.Passphrase = bytes.Clone(auth.Passphrase)
		auth.Password = bytes.Clone(auth.Password)
		if len(auth.PrivateKey) != 0 {
			var signer ssh.Signer
			var err error
			if len(auth.Passphrase) != 0 {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(auth.PrivateKey, auth.Passphrase)
			} else {
				signer, err = ssh.ParsePrivateKey(auth.PrivateKey)
			}
			if err != nil {
				// Do not include parser errors, credential names or secret material.
				return nil, errors.New("sshrunner: invalid private key or passphrase")
			}
			methods[name] = append(methods[name], ssh.PublicKeys(signer))
		}
		if len(auth.Password) != 0 {
			methods[name] = append(methods[name], ssh.Password(string(auth.Password)))
		}
		auths[name] = auth
	}
	if len(auths) == 0 {
		return nil, errors.New("sshrunner: credentials are required")
	}
	cfg.Auths = auths
	cfg.KnownHostsFiles = append([]string(nil), cfg.KnownHostsFiles...)
	var targets map[agentless.Target]struct{}
	if cfg.Targets != nil {
		cfg.Targets = append([]agentless.Target{}, cfg.Targets...)
		targets = make(map[agentless.Target]struct{}, len(cfg.Targets))
		for _, target := range cfg.Targets {
			target, err := normalizeTarget(target)
			if err != nil {
				return nil, err
			}
			if _, ok := auths[target.Auth]; !ok {
				return nil, errors.New("sshrunner: target selects an undefined auth")
			}
			targets[target] = struct{}{}
		}
	}
	for _, pair := range [][2]*time.Duration{
		{&cfg.DialTimeout, &DefaultConfig.DialTimeout}, {&cfg.Timeout, &DefaultConfig.Timeout},
		{&cfg.KeepaliveInterval, &DefaultConfig.KeepaliveInterval}, {&cfg.KeepaliveTimeout, &DefaultConfig.KeepaliveTimeout},
		{&cfg.IdleTimeout, &DefaultConfig.IdleTimeout},
		{&cfg.ReconnectBackoffMin, &DefaultConfig.ReconnectBackoffMin}, {&cfg.ReconnectBackoffMax, &DefaultConfig.ReconnectBackoffMax},
		{&cfg.AuthFailureBackoffMin, &DefaultConfig.AuthFailureBackoffMin}, {&cfg.AuthFailureBackoffMax, &DefaultConfig.AuthFailureBackoffMax},
	} {
		if *pair[0] == 0 {
			*pair[0] = *pair[1]
		}
		if *pair[0] <= 0 {
			return nil, errors.New("sshrunner: timeouts and backoffs must be positive")
		}
	}
	if cfg.MaxSessionsPerTarget == 0 {
		cfg.MaxSessionsPerTarget = DefaultConfig.MaxSessionsPerTarget
	}
	if cfg.MaxConcurrentDials == 0 {
		cfg.MaxConcurrentDials = DefaultConfig.MaxConcurrentDials
	}
	if cfg.Limits.MaxSectionBytes == 0 {
		cfg.Limits.MaxSectionBytes = DefaultConfig.Limits.MaxSectionBytes
	}
	if cfg.Limits.MaxOutputBytes == 0 {
		cfg.Limits.MaxOutputBytes = DefaultConfig.Limits.MaxOutputBytes
	}
	if cfg.MaxSessionsPerTarget < 1 || cfg.MaxSessionsPerTarget >= 10 || cfg.MaxConcurrentDials < 1 || cfg.Limits.MaxSectionBytes < 1 || cfg.Limits.MaxOutputBytes < 1 || cfg.ReconnectBackoffMax < cfg.ReconnectBackoffMin || cfg.AuthFailureBackoffMax < cfg.AuthFailureBackoffMin {
		return nil, errors.New("sshrunner: invalid session, dial, output or backoff limits")
	}
	if cfg.KnownHosts == "" && len(cfg.KnownHostsFiles) == 0 {
		return nil, errors.New("sshrunner: known_hosts content or files are required")
	}
	contents, err := combinedKnownHosts(cfg.KnownHosts, cfg.KnownHostsFiles)
	if err != nil {
		return nil, err
	}
	keys, err := parseKnownHosts(contents)
	if err != nil {
		return nil, err
	}
	return &settings{Config: cfg, methods: methods, targets: targets, hostKeys: keys}, nil
}

const maxKnownHostsBytes = 4 << 20

// combinedKnownHosts is shared by preparation and reload so verification and
// connection identity always use the same snapshot of both trust sources.
func combinedKnownHosts(inline string, files []string) ([]byte, error) {
	if len(inline) > maxKnownHostsBytes {
		return nil, errors.New("sshrunner: known_hosts content exceeds 4 MiB")
	}
	contents, err := readKnownHosts(files)
	if err != nil {
		return nil, err
	}
	if inline != "" {
		contents = append(contents, inline...)
		contents = append(contents, '\n')
	}
	return contents, nil
}

func readKnownHosts(files []string) ([]byte, error) {
	var contents []byte
	for _, name := range files {
		data, err := readKnownHostsFile(name)
		if err != nil {
			return nil, fmt.Errorf("sshrunner: read known_hosts: %w", err)
		}
		contents = append(contents, data...)
		contents = append(contents, '\n')
	}
	return contents, nil
}

func readKnownHostsFile(name string) ([]byte, error) {
	// Reject devices before opening them. Nonblocking open also handles a
	// regular file replaced with a FIFO between Stat and Open.
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("known_hosts must be a regular file")
	}
	if info.Size() > maxKnownHostsBytes {
		return nil, errors.New("known_hosts exceeds 4 MiB")
	}
	f, err := openKnownHosts(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("known_hosts must be a regular file")
	}
	if info.Size() > maxKnownHostsBytes {
		return nil, errors.New("known_hosts exceeds 4 MiB")
	}
	// Bound reads even if an opened regular file grows after Stat.
	data, err := io.ReadAll(io.LimitReader(f, maxKnownHostsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKnownHostsBytes {
		return nil, errors.New("known_hosts exceeds 4 MiB")
	}
	return data, nil
}

func parseKnownHosts(contents []byte) (*hostKeys, error) {
	// Verification, algorithm selection and the fingerprint all use the same
	// private snapshot, including when a source file is atomically replaced.
	f, err := os.CreateTemp("", "alloy-ssh-known-hosts-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	verify, err := knownhosts.New(f.Name())
	if err != nil {
		// Parser errors can quote trust input from secret-producing components.
		// New and Update diagnostics must never expose those bytes.
		return nil, errors.New("sshrunner: invalid known_hosts content")
	}
	certLines := make(map[int]bool)
	for i, line := range strings.Split(string(contents), "\n") {
		certLines[i+1] = strings.HasPrefix(strings.TrimSpace(line), "@cert-authority ") || strings.HasPrefix(strings.TrimSpace(line), "@cert-authority\t")
	}
	return &hostKeys{trust: sha256.Sum256(contents), verify: verify, certLines: certLines}, nil
}

func (s *settings) permits(target agentless.Target) bool {
	if s.targets == nil {
		return true
	}
	_, ok := s.targets[target]
	return ok
}

// A deliberately unmatched key asks the knownhosts parser for all matching
// records. That reuses its hashed-host, wildcard, negation and port semantics.
type unmatchedKey struct{}

func (unmatchedKey) Type() string                        { return "unmatched" }
func (unmatchedKey) Marshal() []byte                     { return nil }
func (unmatchedKey) Verify([]byte, *ssh.Signature) error { return errors.New("unmatched key") }

func (s *settings) algorithms(address string) []string {
	var keyErr *knownhosts.KeyError
	if !errors.As(s.verify(address, &net.TCPAddr{}, unmatchedKey{}), &keyErr) {
		return nil
	}
	allowed := make(map[string]bool)
	for _, want := range keyErr.Want {
		if s.certLines[want.Line] {
			// A CA can sign any supported host key type; its own key type
			// does not constrain the certified host key's algorithm.
			for _, alg := range ssh.SupportedAlgorithms().HostKeys {
				if strings.Contains(alg, "-cert-v01@openssh.com") {
					allowed[alg] = true
				}
			}
		} else if want.Key.Type() == ssh.KeyAlgoRSA {
			allowed[ssh.KeyAlgoRSASHA512] = true
			allowed[ssh.KeyAlgoRSASHA256] = true
		} else {
			allowed[want.Key.Type()] = true
		}
	}
	var result []string
	for _, alg := range ssh.SupportedAlgorithms().HostKeys {
		if allowed[alg] {
			result = append(result, alg)
		}
	}
	return result
}

func sameIdentity(a, b *settings, auth string) bool {
	return a.trust == b.trust && reflect.DeepEqual(a.Auths[auth], b.Auths[auth])
}
