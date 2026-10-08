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
		if isReadlinkCommand(r) && !isReadlink(r) {
			return fmt.Errorf("read %q must be readlink -f of a safe absolute path", r.ID)
		}
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

// isReadlinkCommand also identifies noncanonical executable paths so they
// cannot bypass the fixed command form or phase restrictions.
func isReadlinkCommand(r Read) bool {
	return len(r.Argv) != 0 && (r.Argv[0] == "readlink" || strings.HasSuffix(r.Argv[0], "/readlink"))
}

func isReadlink(r Read) bool {
	return r.Path == "" && len(r.Argv) == 3 && r.Argv[0] == "readlink" && r.Argv[1] == "-f" && safeReadlinkPath(r.Argv[2])
}

// Match the file/listing path alphabet without regexp allocations on output
// validation paths. A resolved path is not admitted as a new command here.
func safeReadlinkPath(path string) bool {
	if len(path) < 2 || path[0] != '/' || strings.Contains(path, "..") {
		return false
	}
	for i := 1; i < len(path); i++ {
		c := path[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '/' || c == '-') {
			return false
		}
	}
	return true
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
	if isReadlinkCommand(r) {
		// A readlink result is one path of at most 4096 bytes, optionally
		// terminated by exactly one LF. Never expose a partial or multiline
		// result, even if a runner did not set Truncated.
		line := res.Output
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 4096 || !safeReadlinkPath(string(line)) {
			return nil, fmt.Errorf("read %q did not return one bounded absolute path", r.ID)
		}
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
// Expand may return file reads, CommandRead("ls", "-1", directory), and
// CommandRead("readlink", "-f", path) reads derived from phase-one listings.
// All reads must pass Validate. The two expansions share MaxDeepListings for
// phase-two listings and readlink reads in either expansion, unless the collector
// implements DeepListingLimiter.
// ExpandDeep is called once after phase two, with the combined phase-one and
// phase-two results. It returns validated file or readlink reads, never listings;
// there is no recursion or fourth phase. Update receives all three phases.
// The two expansions share MaxExpandedReads and MaxExpandedReadsPerScrape.
// Like Expand and Update, ExpandDeep must be safe for concurrent targets. A
// failure in either expansion skips only this collector's Update.
type DeepExpander interface {
	Expander
	ExpandDeep(target Target, in Input) ([]Read, error)
}

// MaxDeepListingsCeiling is the largest limit a DeepListingLimiter may declare.
// The shared expanded-read budgets still apply independently of this limit.
const MaxDeepListingsCeiling = 512

// DeepListingLimiter optionally sets a DeepExpander's combined limit for
// phase-two listings and readlink reads across both expansions. Without it,
// MaxDeepListings applies. A declaration outside [1, MaxDeepListingsCeiling]
// fails only that collector for the scrape, before either expansion runs.
// DeepListingLimit must be constant and safe for concurrent scrapes.
// This interface has no effect on collectors that are not DeepExpanders.
type DeepListingLimiter interface {
	DeepListingLimit() int
}
