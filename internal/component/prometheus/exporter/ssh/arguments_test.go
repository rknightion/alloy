package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/component/discovery"
)

func TestPoolConfigTargetMembership(t *testing.T) {
	for _, tc := range []struct {
		name string
		args Arguments
		want []agentless.Target
	}{
		{
			name: "blocks",
			args: Arguments{Targets: []Target{{Name: "one", Address: "host", Auth: "reader", Labels: map[string]string{"env": "test"}}, {Address: "[::1]:2222"}}},
			want: []agentless.Target{{Address: "host", Auth: "reader"}, {Address: "[::1]:2222"}},
		},
		{
			name: "discovery",
			args: Arguments{TargetsList: []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host:2222", "name": "one"}), discovery.NewTargetFromMap(map[string]string{"address": "other"})}},
			want: []agentless.Target{{Address: "host:2222"}, {Address: "other"}},
		},
		{name: "empty", want: []agentless.Target{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.args.poolConfig()
			require.NotNil(t, cfg.Targets, "empty component membership must prune all destinations, not allow any")
			require.Equal(t, tc.want, cfg.Targets)
		})
	}
}
