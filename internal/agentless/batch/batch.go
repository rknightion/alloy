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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

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
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Build returns the sh script that runs reads in order under nonce. It
// returns an error when any read fails agentless.Read.Validate or the nonce is
// malformed.
func Build(reads []agentless.Read, nonce string) (string, error) {
	if err := validate(reads, nonce); err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("exec 2>/dev/null\n")
	for i, read := range reads {
		fmt.Fprintf(&script, "printf '%s:%d:begin\\n'\nmissing=0\n", nonce, i)
		if read.Path != "" {
			fmt.Fprintf(&script, "if [ -e %s ]; then\ncat %s\nstatus=$?\nelse\nstatus=1\nmissing=1\nfi\n", read.Path, read.Path)
		} else {
			fmt.Fprintf(&script, "if command -v %s >/dev/null 2>&1; then\n( %s )\nstatus=$?\nelse\nstatus=127\nmissing=1\nfi\n", read.Argv[0], strings.Join(read.Argv, " "))
		}
		fmt.Fprintf(&script, "printf '\\n%s:%d:end:%%s:%%s\\n' \"$status\" \"$missing\"\n", nonce, i)
	}
	return script.String(), nil
}

func validate(reads []agentless.Read, nonce string) error {
	if len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return errors.New("batch: malformed nonce")
	}
	for _, read := range reads {
		if err := read.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Demux reads the output of a script built by Build with the same reads and
// nonce, and returns one Result per read, in order, setting ExitStatus,
// NotExist and Truncated from the framing. When ctx ends or r fails mid-batch,
// it returns the completed sections and marks the rest TimedOut. It returns an
// error when the framing is malformed, the output exceeds
// limits.MaxOutputBytes, or nothing arrived before ctx ended.
func Demux(ctx context.Context, r io.Reader, nonce string, reads []agentless.Read, limits Limits) ([]agentless.Result, error) {
	if err := validate(reads, nonce); err != nil {
		return nil, err
	}
	if limits.MaxSectionBytes <= 0 || limits.MaxOutputBytes <= 0 {
		return nil, errors.New("batch: limits must be positive")
	}
	p := parser{nonce: nonce, limits: limits, results: make([]agentless.Result, len(reads))}
	for i, read := range reads {
		p.results[i] = agentless.Result{Read: read, TimedOut: true}
	}
	// The runner owns the stream and must close it when abandoning a session.
	// Only one bounded read is outstanding; cancellation does not wait for it.
	type chunk struct {
		data []byte
		err  error
	}
	chunks := make(chan chunk)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := r.Read(buf)
			select {
			case chunks <- chunk{buf[:n], err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return p.partial(ctx.Err())
		case c := <-chunks:
			for _, b := range c.data {
				p.total++
				if p.total > limits.MaxOutputBytes {
					return nil, errors.New("batch: total output limit exceeded")
				}
				if err := p.byte(b); err != nil {
					return nil, err
				}
			}
			if c.err != nil {
				if p.index == len(reads) && len(p.line) == 0 && errors.Is(c.err, io.EOF) {
					return p.results, nil
				}
				return p.partial(c.err)
			}
		}
	}
}

// parser retains only a possible framing line and the capped section output.
// Payload lines longer than a framing line are drained without buffering.
type parser struct {
	nonce              string
	limits             Limits
	results            []agentless.Result
	index, total, size int
	active, payload    bool
	line               []byte
}

func (p *parser) append(b byte) {
	if p.size < p.limits.MaxSectionBytes {
		p.results[p.index].Output = append(p.results[p.index].Output, b)
	}
	p.size++
}

func (p *parser) byte(b byte) error {
	if p.index >= len(p.results) {
		return errors.New("batch: trailing output")
	}
	if p.payload {
		p.append(b)
		if b == '\n' {
			p.payload = false
		}
		return nil
	}
	p.line = append(p.line, b)
	prefix := fmt.Sprintf("%s:%d:", p.nonce, p.index)
	if !p.active {
		expected := prefix + "begin\n"
		if !strings.HasPrefix(expected, string(p.line)) {
			return errors.New("batch: malformed section start")
		}
		if len(p.line) == len(expected) {
			p.active = true
			p.line = nil
			p.size = 0
		}
		return nil
	}
	marker := prefix + "end:"
	possible := strings.HasPrefix(marker, string(p.line)) || strings.HasPrefix(string(p.line), marker)
	if possible && len(p.line) <= len(marker)+8 {
		if b != '\n' {
			return nil
		}
		fields := strings.Split(strings.TrimSuffix(string(p.line), "\n"), ":")
		if len(fields) != 5 {
			return errors.New("batch: malformed section end")
		}
		status, err := strconv.Atoi(fields[3])
		if err != nil || status < 0 || status > 255 || (fields[4] != "0" && fields[4] != "1") || (fields[4] == "1" && status == 0) || p.size == 0 {
			return errors.New("batch: invalid section status")
		}
		res := &p.results[p.index]
		// Build adds one separator newline, not part of the read's output.
		if p.size <= p.limits.MaxSectionBytes {
			res.Output = res.Output[:len(res.Output)-1]
		}
		p.size--
		res.Truncated = p.size > p.limits.MaxSectionBytes
		res.ExitStatus, res.NotExist, res.TimedOut = status, fields[4] == "1", false
		p.index++
		p.active = false
		p.line = nil
		return nil
	}
	for _, v := range p.line {
		p.append(v)
	}
	p.line = nil
	p.payload = b != '\n'
	return nil
}

func (p *parser) partial(err error) ([]agentless.Result, error) {
	if p.index == 0 && !p.active {
		return nil, fmt.Errorf("batch: no trusted section: %w", err)
	}
	if p.active && p.index < len(p.results) {
		for _, b := range p.line {
			p.append(b)
		}
		p.results[p.index].Truncated = p.size > p.limits.MaxSectionBytes
	}
	return p.results, nil
}
