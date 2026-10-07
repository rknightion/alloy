package positions

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/runtime/logging"
)

func TestPresenceAndSnapshotOnDisk(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "positions.yaml")
	require.NoError(t, os.WriteFile(filename, []byte(`positions:
  ? path: cursor-test/empty
    labels: ''
  : ''
  ? path: cursor-test/zero
    labels: ''
  : '0'
  ? path: cursor-test/zero
    labels: '{job="variant"}'
  : 'not a checkpoint'
  ? path: other/cursor-test/zero
    labels: 'cursor-test/'
  : 'outside'
`), 0600))
	cfg := Config{PositionsFile: filename, SyncPeriod: time.Hour}
	p, err := New(logging.NewSlogNop(), cfg)
	require.NoError(t, err)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			p.Stop()
		}
	})

	for _, tc := range []struct {
		path    string
		labels  string
		value   string
		present bool
	}{
		{"cursor-test/absent", "", "", false},
		{"cursor-test/empty", "", "", true},
		{"cursor-test/zero", "", "0", true},
		{"cursor-test/zero", `{job="variant"}`, "not a checkpoint", true},
		{"cursor-test/zero", "other labels", "", false},
	} {
		value, present := p.LookupString(tc.path, tc.labels)
		require.Equal(t, tc.value, value)
		require.Equal(t, tc.present, present, "path=%s labels=%s", tc.path, tc.labels)
		require.Equal(t, tc.value, p.GetString(tc.path, tc.labels))
	}

	want := map[Entry]string{
		{Path: "cursor-test/empty"}:                           "",
		{Path: "cursor-test/zero"}:                            "0",
		{Path: "cursor-test/zero", Labels: `{job="variant"}`}: "not a checkpoint",
	}
	for _, limit := range []int{3, 4} {
		snapshot, err := p.SnapshotPrefix("cursor-test/", limit)
		require.NoError(t, err)
		require.Equal(t, want, snapshot)
	}
	for _, limit := range []int{1, 2} {
		snapshot, err := p.SnapshotPrefix("cursor-test/", limit)
		require.ErrorIs(t, err, ErrEntryLimit)
		require.Nil(t, snapshot)
	}
	for _, tc := range []struct {
		prefix string
		limit  int
	}{{"", 3}, {"cursor-test/", 0}, {"cursor-test/", -1}} {
		snapshot, err := p.SnapshotPrefix(tc.prefix, tc.limit)
		require.Error(t, err)
		require.Nil(t, snapshot)
	}
	empty, err := p.SnapshotPrefix("missing/", 1)
	require.NoError(t, err)
	require.NotNil(t, empty)
	require.Empty(t, empty)

	snapshot, err := p.SnapshotPrefix("cursor-test/", 3)
	require.NoError(t, err)
	snapshot[Entry{Path: "cursor-test/zero"}] = "changed"
	delete(snapshot, Entry{Path: "cursor-test/empty"})
	snapshot[Entry{Path: "cursor-test/new"}] = "injected"
	unchanged, err := p.SnapshotPrefix("cursor-test/", 3)
	require.NoError(t, err)
	require.Equal(t, want, unchanged)

	p.PutString("cursor-test/zero", "", "new progress")
	require.Equal(t, "changed", snapshot[Entry{Path: "cursor-test/zero"}])
	p.Stop()
	stopped = true
	p, err = New(logging.NewSlogNop(), cfg)
	require.NoError(t, err)
	stopped = false
	value, present := p.LookupString("cursor-test/empty", "")
	require.True(t, present)
	require.Empty(t, value)
	value, present = p.LookupString("cursor-test/zero", "")
	require.True(t, present)
	require.Equal(t, "new progress", value)
	_, present = p.LookupString("cursor-test/new", "")
	require.False(t, present)
}

func TestPresenceSnapshotConcurrent(t *testing.T) {
	p, err := New(logging.NewSlogNop(), Config{
		PositionsFile: filepath.Join(t.TempDir(), "positions.yaml"),
		SyncPeriod:    time.Hour,
	})
	require.NoError(t, err)
	defer p.Stop()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				p.PutString("cursor-test/key", "", "0")
				p.LookupString("cursor-test/key", "")
				snapshot, err := p.SnapshotPrefix("cursor-test/", 1)
				if err != nil {
					t.Error(err)
				}
				snapshot[Entry{Path: "cursor-test/key"}] = "caller owned"
				p.Remove("cursor-test/key", "")
			}
		})
	}
	wg.Wait()
}
