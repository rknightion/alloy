# Default-collector hostile heap proof

`TestHostileDefaultCollectorsHeap` builds `collectors.DefaultEnabled()` with unchanged default
configuration. It runs each collector through the real `NewScraper` → `Scrape` → Prometheus `Gather`
path. Every declared fixed read has a separate nearly-1-MiB hostile case, with the collector's other
reads valid. A successful ordinary snapshot checks those supporting fixtures. New defaults or reads
without explicit fixtures fail the test rather than receiving the fake runner's missing-file fallback.

Testing reads separately prevents an error in the first read from masking later parser paths. The
`/usr/lib/os-release` case explicitly marks `/etc/os-release` missing to exercise the fallback parser.
The original seven-section corpus and six-collector heap test remain unchanged; the new proof reuses
those exact bytes for their corresponding reads.

The additional inputs cover scalar outputs padded with many whitespace lines, unique md devices,
netstat fields, os-release keys, schedstat CPUs, sockstat protocols, vmstat fields, repeated valid
conntrack and UDP rows, repeated softnet CPU rows, duplicate pressure rows, and oversized uname
labels. Fixtures are generated deterministically inside the test, not read from a remote host.
Expected collector success or rejection is checked, as are real exported data for successful cases,
scrape status presence, and the unchanged per-collector limits: 20,000 data series, 500 data families,
and 4,096 bytes per exported label value. The two scraper-owned status families are counted
separately. Both sampled peak and final heap must stay below the original 64-MiB threshold.

This complements, rather than replaces, the original simultaneous six-collector proof. The new suite
measures each default collector/read individually; it does not claim a simultaneous all-default batch
fits within 64 MiB. Heap sampling retains the original 1-ms sampling limitation.

## Reproduce the negative control without changing the checkout

From the checkout root, run the following Python command. It writes a source copy and a Go overlay
only beneath `/tmp/alloy-loop5-hostile/`. The scratch collector embeds the frozen collector interface,
keeps the real conntrack implementation and fixed reads, but intentionally retains a 4,096-byte
record for each nonempty conntrack statistics line. The retained records survive until after Gather,
so the unchanged heap assertion must reject it. No production seam is edited.

```sh
# Match the physical source path used by the overlay, including macOS /tmp symlinks.
cd "$(pwd -P)"
mkdir -p /tmp/alloy-loop5-hostile
python3 - "$PWD" <<'PY'
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
scratch = pathlib.Path('/tmp/alloy-loop5-hostile')
source = repo / 'internal/agentless/hostile_test.go'
text = source.read_text()
marker = '\trequire.NotEmpty(t, cs)\n'
assert text.count(marker) == 1
text = text.replace(marker, marker + '''\tfor i, c := range cs {
		if c.Name() == "conntrack" {
			cs[i] = &negativeRetainingCollector{Collector: c}
		}
	}
''')
text += '''
type negativeRetainingCollector struct {
	agentless.Collector
	retained [][]byte
}

func (c *negativeRetainingCollector) Update(target agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	read := agentless.FileRead("/proc/net/stat/nf_conntrack")
	for _, line := range strings.Split(string(in[read.ID].Output), "\\n") {
		if line == "" {
			continue
		}
		record := make([]byte, 4096)
		copy(record, line)
		c.retained = append(c.retained, record)
	}
	err := c.Collector.Update(target, in, ch)
	runtime.KeepAlive(c.retained)
	return err
}
'''
overlay_source = scratch / 'negative_hostile_test.go'
overlay_source.write_text(text)
(scratch / 'negative-overlay.json').write_text(json.dumps({
    'Replace': {str(source): str(overlay_source)}
}, indent=2) + '\n')
PY
GOTOOLCHAIN=go1.26.7 go test -race -tags=nodocker,hostile \
  -overlay=/tmp/alloy-loop5-hostile/negative-overlay.json \
  ./internal/agentless -run '^TestHostileDefaultCollectorsHeap/conntrack/read_2$' \
  -count=1 -timeout=5m -v > /tmp/alloy-loop5-hostile/negative-control.log 2>&1
```

Expected: exit 1, with `TestHostileDefaultCollectorsHeap/conntrack/read_2` failing the
`hostile processing must stay below 64 MiB of sampled heap` assertion. Confirm it is a heap assertion
failure, not a compilation error, missing fixture, parse error, or timeout. An observed run retained
about 142 million bytes of heap against the unchanged 67,108,864-byte threshold.

Run the same test without the overlay to establish the positive control:

```sh
GOTOOLCHAIN=go1.26.7 go test -race -tags=nodocker,hostile ./internal/agentless \
  -run '^TestHostileDefaultCollectorsHeap$' -count=1 -timeout=5m -v \
  > /tmp/alloy-loop5-hostile/positive-control.log 2>&1
```

Expected: every baseline and declared-read subtest passes, with collector/read identifiers, input
sizes, exported family/series counts, allocations, and measured heap reported in the log. The overlay
is never used by the regular test command or committed.
