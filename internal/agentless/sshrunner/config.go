package sshrunner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type settings struct {
	Config
	methods   map[string][]ssh.AuthMethod
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
	if len(cfg.KnownHostsFiles) == 0 {
		return nil, errors.New("sshrunner: known_hosts files are required")
	}
	// Parse a private snapshot rather than reading the original files twice.
	// This binds verification, algorithm selection and Update's fingerprint to
	// exactly the same bytes, including when a file is atomically replaced.
	var contents []byte
	for _, name := range cfg.KnownHostsFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("sshrunner: read known_hosts: %w", err)
		}
		contents = append(contents, data...)
		contents = append(contents, '\n')
	}
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
		return nil, fmt.Errorf("sshrunner: parse known_hosts: %w", err)
	}
	certLines := make(map[int]bool)
	for i, line := range strings.Split(string(contents), "\n") {
		certLines[i+1] = strings.HasPrefix(strings.TrimSpace(line), "@cert-authority ") || strings.HasPrefix(strings.TrimSpace(line), "@cert-authority\t")
	}
	return &settings{Config: cfg, methods: methods, trust: sha256.Sum256(contents), verify: verify, certLines: certLines}, nil
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
