package batch

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
)

func fuzzReads() []agentless.Read {
	return []agentless.Read{agentless.FileRead("/proc/stat"), agentless.CommandRead("uname", "-s"), agentless.FileRead("/proc/loadavg")}
}

func frame(nonce string, sections [][]byte, statuses []uint8) []byte {
	var b bytes.Buffer
	for i, s := range sections {
		fmt.Fprintf(&b, "%s:%d:begin\n", nonce, i)
		b.Write(s)
		fmt.Fprintf(&b, "\n%s:%d:end:%d:0\n", nonce, i, statuses[i])
	}
	return b.Bytes()
}

// FuzzDemux feeds arbitrary target output to Demux. A hostile target controls
// every byte it prints, so Demux must never panic or keep more than its limits
// allow, whatever the framing.
func FuzzDemux(f *testing.F) {
	f.Add(frame(testNonce, [][]byte{[]byte("cpu 1 2 3"), []byte("Linux"), []byte("0.1 0.2 0.3 1/2 3")}, []uint8{0, 0, 0}))
	f.Add(frame(testNonce, [][]byte{[]byte(testNonce + ":1:begin"), {}, []byte(testNonce + ":2:end:0:0")}, []uint8{0, 1, 0}))
	f.Add([]byte(testNonce + ":0:begin\n" + strings.Repeat("x", 200)))
	f.Add([]byte(testNonce + ":0:begin\n\n" + testNonce + ":0:end:999:0\n"))
	f.Add([]byte{})
	limits := Limits{MaxSectionBytes: 64, MaxOutputBytes: 1024}
	f.Fuzz(func(t *testing.T, data []byte) {
		reads := fuzzReads()
		results, err := Demux(context.Background(), bytes.NewReader(data), testNonce, reads, limits)
		if err != nil {
			return
		}
		if len(results) != len(reads) {
			t.Fatalf("got %d results for %d reads", len(results), len(reads))
		}
		for i, res := range results {
			if res.Read.ID != reads[i].ID {
				t.Fatalf("result %d is for read %q, want %q", i, res.Read.ID, reads[i].ID)
			}
			if len(res.Output) > limits.MaxSectionBytes {
				t.Fatalf("result %d kept %d bytes, over the %d byte cap", i, len(res.Output), limits.MaxSectionBytes)
			}
			if res.ExitStatus < 0 || res.ExitStatus > 255 {
				t.Fatalf("result %d has exit status %d", i, res.ExitStatus)
			}
		}
	})
}

// FuzzDemuxRoundTrip checks that output which does not contain the per-run
// nonce comes back byte for byte in its own section, so a target cannot move
// data between sections without knowing the nonce.
func FuzzDemuxRoundTrip(f *testing.F) {
	f.Add([]byte("cpu 1 2 3\n"), []byte("Linux"), []byte(""), uint8(0), uint8(1))
	f.Add([]byte(":0:end:0:0\n"), []byte("\n\n"), []byte("deadbeef:2:begin\n"), uint8(2), uint8(0))
	f.Fuzz(func(t *testing.T, a, b, c []byte, sa, sb uint8) {
		sections := [][]byte{a, b, c}
		for _, s := range sections {
			if bytes.Contains(s, []byte(testNonce)) {
				t.Skip("output contains the secret nonce")
			}
		}
		statuses := []uint8{sa, sb, 0}
		results, err := Demux(context.Background(), bytes.NewReader(frame(testNonce, sections, statuses)), testNonce, fuzzReads(), DefaultLimits)
		if err != nil {
			t.Fatalf("well-framed output rejected: %v", err)
		}
		for i, res := range results {
			if !bytes.Equal(res.Output, sections[i]) {
				t.Fatalf("section %d: got %q, want %q", i, res.Output, sections[i])
			}
			if res.ExitStatus != int(statuses[i]) || res.TimedOut || res.Truncated || res.NotExist {
				t.Fatalf("section %d: got %+v, want exit status %d", i, res, statuses[i])
			}
		}
	})
}

// FuzzBuildValidatedRead checks that any read that passes Validate lands in
// the script as a single shell word with no character the shell interprets.
func FuzzBuildValidatedRead(f *testing.F) {
	for _, s := range []string{"/proc/stat", "/proc/stat\n;id", "/proc/$(id)", "-s", "a;b", "--x=1", "../etc", "a b", "/a/..b"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, path, arg string) {
		for _, read := range []agentless.Read{{ID: "file", Path: path}, {ID: "cmd", Argv: []string{"uname", arg}}, {ID: "name", Argv: []string{arg}}} {
			if read.Validate() != nil {
				continue
			}
			if _, err := Build([]agentless.Read{read}, testNonce); err != nil {
				t.Fatalf("validated read %+v failed to build: %v", read, err)
			}
			for _, word := range append([]string{read.Path}, read.Argv...) {
				if strings.Contains(word, "..") {
					t.Fatalf("validated word %q contains ..", word)
				}
				for _, r := range word {
					if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/=:+-", r) {
						t.Fatalf("validated word %q contains %q, which the shell may interpret", word, r)
					}
				}
			}
		}
	})
}
