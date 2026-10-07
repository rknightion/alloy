// Package agentless collects host metrics from remote targets by running a
// fixed, compiled-in set of read-only commands over a remote transport such as
// SSH, and parses their output into node_exporter-compatible metrics.
//
// The package is independent of Alloy component types so that it can back an
// Alloy component, a standalone exporter or another collector distribution.
//
// Three seams make up the package:
//
//   - A Read is one fixed file or command. Collectors declare their reads at
//     compile time; no configuration or target value ever becomes part of a
//     command.
//   - A Runner executes a batch of reads against one target and returns one
//     Result per read.
//   - A Collector parses the results of its own reads into metrics.
//
// A Scraper ties them together for one scrape of one target.
package agentless

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrNotImplemented is returned by stub implementations of the seams.
var ErrNotImplemented = errors.New("agentless: not implemented")

var (
	// pathPattern restricts file reads to absolute paths made of characters
	// that never need shell quoting.
	pathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	// commandPattern restricts a command name to characters that never need
	// shell quoting and cannot form a shell variable assignment.
	commandPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	// argPattern restricts command arguments to characters that never need
	// shell quoting.
	argPattern = regexp.MustCompile(`^[A-Za-z0-9._/=:+-]+$`)
)

// Read is one fixed, read-only operation on a target: either reading a file
// or running a command with fixed arguments. Reads are compiled into
// collectors and never built from configuration or target data.
type Read struct {
	// ID uniquely identifies the read within a batch. Collectors that declare
	// the same read share one execution of it.
	ID string
	// Path is the absolute path of the file to read. Exactly one of Path and
	// Argv is set.
	Path string
	// Argv is the command and its fixed arguments.
	Argv []string
}

// FileRead returns a Read that reads the file at path.
func FileRead(path string) Read {
	return Read{ID: "file:" + path, Path: path}
}

// CommandRead returns a Read that runs argv.
func CommandRead(argv ...string) Read {
	return Read{ID: "cmd:" + strings.Join(argv, " "), Argv: argv}
}

// Validate reports whether r can be placed in a batch without quoting. Every
// component of a valid Read matches a conservative character set, so a batch
// builder never has to escape anything.
func (r Read) Validate() error {
	switch {
	case r.ID == "":
		return errors.New("read has no ID")
	case r.Path != "" && len(r.Argv) != 0:
		return fmt.Errorf("read %q sets both a path and a command", r.ID)
	case r.Path != "":
		if !pathPattern.MatchString(r.Path) || strings.Contains(r.Path, "..") {
			return fmt.Errorf("read %q has an unsafe path %q", r.ID, r.Path)
		}
	case len(r.Argv) != 0:
		if !commandPattern.MatchString(r.Argv[0]) {
			return fmt.Errorf("read %q has an unsafe command %q", r.ID, r.Argv[0])
		}
		for _, a := range r.Argv {
			if !argPattern.MatchString(a) || strings.Contains(a, "..") {
				return fmt.Errorf("read %q has an unsafe argument %q", r.ID, a)
			}
		}
	default:
		return fmt.Errorf("read %q sets neither a path nor a command", r.ID)
	}
	return nil
}

// Result is the outcome of one Read.
type Result struct {
	Read Read
	// Output is the read's standard output, up to the runner's byte cap.
	// Standard error is discarded.
	Output []byte
	// ExitStatus is the exit status of the read on the target. Zero means
	// success. Some commands exit non-zero with useful output (GNU df exits 1
	// when one mount cannot be read), so a collector may still parse Output.
	ExitStatus int
	// NotExist is true when the file does not exist or the command is not
	// installed on the target. ExitStatus is then non-zero.
	NotExist bool
	// Truncated is true when Output was cut at the byte cap.
	Truncated bool
	// TimedOut is true when the batch deadline passed before the read
	// finished. Output then holds whatever arrived before the deadline.
	TimedOut bool
}

// Target identifies one remote host.
type Target struct {
	// Address is host or host:port. Runners apply their default port when
	// the port is missing.
	Address string
	// Auth names the credentials a Runner uses for this target. Empty means
	// the Runner's default credentials.
	Auth string
}

// Runner executes a batch of reads against one target.
//
// Run returns exactly one Result per read, in the order of reads. A read that
// fails on the target is reported through its Result and does not fail the
// batch. When ctx's deadline passes mid-batch, Run returns the reads that
// completed and marks the rest TimedOut, so one hung read (df on a stale NFS
// mount) costs only the collectors that need it. Run returns an error only when
// no result can be trusted: the target is unreachable, authentication or host
// key verification failed, the output framing is malformed, or ctx ended before
// any output arrived. A Runner must release any remote session it abandons.
type Runner interface {
	Run(ctx context.Context, target Target, reads []Read) ([]Result, error)
}

// Input holds the results of a scrape's batches, keyed by Read.ID.
type Input map[string]Result

// Output returns the output of read r. It returns an error when the read is
// missing from the batch, exited non-zero, was truncated, or timed out. It is a
// convenience for the common case; a collector that accepts a non-zero exit or
// a missing file reads in[r.ID] directly.
func (in Input) Output(r Read) ([]byte, error) {
	res, ok := in[r.ID]
	switch {
	case !ok:
		return nil, fmt.Errorf("read %q missing from batch", r.ID)
	case res.TimedOut:
		return nil, fmt.Errorf("read %q timed out", r.ID)
	case res.ExitStatus != 0:
		return nil, fmt.Errorf("read %q exited with status %d", r.ID, res.ExitStatus)
	case res.Truncated:
		return nil, fmt.Errorf("read %q output exceeded the byte cap", r.ID)
	}
	return res.Output, nil
}

// Collector parses the output of its fixed reads into metrics.
//
// One Collector instance serves every target of a component, and Update is
// called concurrently for different targets. Any state a collector keeps
// between scrapes (such as node_exporter's guard against CPU counters that run
// backwards) must be keyed by Target and safe for concurrent use.
type Collector interface {
	// Name is the collector name, as used by node_exporter and in the
	// collector label of node_scrape_collector_success.
	Name() string
	// Reads returns the fixed reads the collector needs. The result must be
	// the same on every call.
	Reads() []Read
	// Update parses the results of one scrape of target and sends the
	// resulting metrics to ch. An error marks the collector as failed for this
	// scrape. Metrics sent before the error are still exported. A panic is
	// recovered by the Scraper and counts as an error.
	Update(target Target, in Input, ch chan<- prometheus.Metric) error
}

// Expander optionally adds one bounded batch of reads after the fixed Reads
// have completed. A listing uses CommandRead("ls", "-1", fixedDirectory);
// Expand may derive file paths from its output, but every returned Read must
// pass Validate. Expand is called once per scrape, never recursively, and must
// be safe for concurrent calls for different targets, just like Update.
// Update receives the combined results of both phases. An expansion failure
// skips only this collector's Update.
type Expander interface {
	Collector
	Expand(target Target, in Input) ([]Read, error)
}

// DeepExpander optionally discovers files through a second level of listings.
// Expand may return file reads and CommandRead("ls", "-1", directory) reads
// derived from the fixed phase-one listings. All reads must pass Validate, and
// at most MaxDeepListings listings may be returned per collector.
// ExpandDeep is called once after phase two, with the combined phase-one and
// phase-two results. It returns only validated file reads, never more listings;
// there is no recursion or fourth phase. Update receives all three phases.
// The two expansions share MaxExpandedReads and MaxExpandedReadsPerScrape.
// Like Expand and Update, ExpandDeep must be safe for concurrent targets. A
// failure in either expansion skips only this collector's Update.
type DeepExpander interface {
	Expander
	ExpandDeep(target Target, in Input) ([]Read, error)
}
