package collectors

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/grafana/alloy/internal/agentless"
)

// FuzzCollectors feeds arbitrary output to every registered collector. A
// hostile target controls everything its reads print, so Update must never
// panic (the Scraper's recovery is a backstop, not the design), every metric
// it emits must be valid, and the number of series must stay proportional to
// the input. A NUL byte splits the input into one output per read, so
// collectors with several reads see different data for each.
func FuzzCollectors(f *testing.F) {
	err := filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			f.Add(data, uint8(0), false)
		}
		return err
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("cpu0 1 2 3 4 5 6 7 8 9 10\ncpu0 1\x00\xff\xfe 1 2 3"), uint8(1), false)
	f.Add([]byte("Filesystem Type 1024-blocks Used Available Capacity Mounted on\n\xff ext4 1 2 3 4% /\x00/dev/x / ext4 rw 0 0"), uint8(1), true)
	f.Fuzz(func(t *testing.T, data []byte, status uint8, truncated bool) {
		outputs := bytes.Split(data, []byte{0})
		for _, reg := range Registered() {
			c, err := reg.Factory(DefaultConfigs(), nil)
			if err != nil {
				t.Fatalf("collector %s: %v", reg.Name, err)
			}
			in := agentless.Input{}
			for i, r := range c.Reads() {
				in[r.ID] = agentless.Result{Read: r, Output: outputs[i%len(outputs)], ExitStatus: int(status), Truncated: truncated}
			}
			for range 2 { // twice, so stateful collectors compare against their own previous scrape
				updateChecked(t, c, in, bytes.Count(data, []byte{'\n'})+1)
			}
		}
	})
}

func updateChecked(t *testing.T, c agentless.Collector, in agentless.Input, lines int) {
	t.Helper()
	ch := make(chan prometheus.Metric)
	done := make(chan []prometheus.Metric)
	go func() {
		var got []prometheus.Metric
		for m := range ch {
			got = append(got, m)
		}
		done <- got
	}()
	func() {
		defer close(ch)
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("collector %s panicked: %v", c.Name(), p)
			}
		}()
		_ = c.Update(agentless.Target{Address: "fuzz"}, in, ch)
	}()
	got := <-done
	// The widest collector emits 17 series per input line (diskstats).
	if limit := 17*lines + 17; len(got) > limit {
		t.Fatalf("collector %s emitted %d series from %d lines", c.Name(), len(got), lines)
	}
	for _, m := range got {
		if err := m.Write(&dto.Metric{}); err != nil {
			t.Fatalf("collector %s emitted an invalid metric: %v", c.Name(), err)
		}
	}
}

// FuzzTargetLabel checks that label repair keeps distinct target names
// distinct, so two hostile names cannot collapse into one series.
func FuzzTargetLabel(f *testing.F) {
	f.Add("eth0", "\xe8")
	f.Add("\xe8", `"\xe8"`)
	f.Fuzz(func(t *testing.T, a, b string) {
		la, lb := targetLabel(a), targetLabel(b)
		if !utf8.ValidString(la) {
			t.Fatalf("label %q is not valid UTF-8", la)
		}
		if a != b && la == lb {
			t.Fatalf("%q and %q both became %q", a, b, la)
		}
	})
}
