---
canonical: https://grafana.com/docs/alloy/latest/reference/components/prometheus/prometheus.exporter.ssh/
description: Collect Linux host metrics over SSH
labels:
  stage: experimental
  products:
    - oss
title: prometheus.exporter.ssh
---

# `prometheus.exporter.ssh`

`prometheus.exporter.ssh` collects node_exporter-compatible metrics from Linux hosts over SSH without installing an exporter on those hosts.
Grafana Alloy runs compiled-in, read-only commands and reuses SSH connections between scrapes.

{{< docs/shared lookup="stability/experimental.md" source="alloy" version="<ALLOY_VERSION>" >}}

Before you begin, provide an SSH account, credentials, and a verified OpenSSH `known_hosts` file.
You can specify multiple `prometheus.exporter.ssh` components by giving them different labels.

## Usage

```alloy
prometheus.exporter.ssh "<LABEL>" {
	known_hosts_files = ["<KNOWN_HOSTS_FILE>"]

	auth "default" {
		username    = "<SSH_USERNAME>"
		private_key = "<PRIVATE_KEY_CONTENT>"
	}

	target "host" {
		address = "<SSH_HOST>"
	}
}
```

## Arguments

You can use the following arguments with `prometheus.exporter.ssh`:

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `known_hosts_files` | `list(string)` | Paths to verified OpenSSH host key files. | | yes |
| `dial_timeout` | `duration` | Limit for TCP connection and SSH handshake. | `"5s"` | no |
| `enabled_collectors` | `list(string)` | Names of collectors to enable. | | no |
| `idle_timeout` | `duration` | Close connections unused for this duration. | `"5m"` | no |
| `keepalive_interval` | `duration` | Interval between idle connection probes. | `"15s"` | no |
| `keepalive_timeout` | `duration` | Limit for a connection probe. | `"5s"` | no |
| `max_concurrent_dials` | `number` | Maximum concurrent connection attempts. | `16` | no |
| `max_sessions_per_target` | `number` | Maximum concurrent sessions on a target. | `2` | no |
| `targets` | `list(map(string))` | SSH destinations supplied by discovery components. | | no |
| `timeout` | `duration` | Maximum duration of one SSH batch. | `"10s"` | no |

Use either `target` blocks or the `targets` argument, not both.
Discovery targets use `address` or `__address__` for the SSH destination and the `default` auth block for credentials.
Discovery labels don't select credentials.

An empty `enabled_collectors` list enables the default collectors: `cpu`, `diskstats`, `filesystem`, `loadavg`, `meminfo`, `netdev`, `os`, `stat`, and `uname`.
Unknown or duplicate collector names cause a configuration error.
Timeouts must be positive, `max_concurrent_dials` must be at least `1`, and `max_sessions_per_target` must be between `1` and `9`.
Addresses must be unique, including equivalent host and port forms.
An empty target list is valid.

The metrics handler accepts exactly one configured destination through its `target` query parameter.
Missing, repeated, empty, or unknown targets return HTTP `400`.
Transport failures, untrustworthy batch framing, and deadlines before any output return HTTP `503`.
When a scrape includes `X-Prometheus-Scrape-Timeout-Seconds`, the batch deadline subtracts `500ms` from that value and is capped by `timeout`.
Invalid, non-finite, or non-positive header values, and budgets of `500ms` or less, return HTTP `400`.
Without the header, the batch uses `timeout`.

### Collectors

All supported collectors target Linux and are enabled by default.
The runner combines their fixed reads into one SSH execution per scrape and shares duplicate reads.
You can't supply custom commands.

| Name | Fixed reads | Metrics |
| ---- | ----------- | ------- |
| `cpu` | `/proc/stat`. | CPU time counters (`node_cpu_seconds_total`). |
| `diskstats` | `/proc/diskstats`. | Disk I/O counters and gauges (`node_disk_*`). |
| `filesystem` | `env LC_ALL=C df -akPT`, `env LC_ALL=C df -aiPT`, and `/proc/self/mounts`. | Space, inode, read-only, and device-error gauges (`node_filesystem_*`). |
| `loadavg` | `/proc/loadavg`. | Load averages (`node_load1`, `node_load5`, and `node_load15`). |
| `meminfo` | `/proc/meminfo`. | Memory gauges (`node_memory_*`). |
| `netdev` | `/proc/net/dev`. | Network receive and transmit counters (`node_network_*`). |
| `os` | `/etc/os-release`, with `/usr/lib/os-release` as fallback. | OS identity (`node_os_info`). |
| `stat` | `/proc/stat`. | Boot time, context switches, interrupts, forks, and running or blocked processes. |
| `uname` | `uname -s`, `uname -n`, `uname -r`, `uname -v`, `uname -m`, and `/proc/sys/kernel/domainname`. | Kernel and host identity (`node_uname_info`). |

The metric names are compatible with node_exporter for the supported families, not its entire collector set.
CPU families derived from CPU information or `/sys`, and network families derived from netlink, aren't collected.
The parser tests compare supported families against node_exporter fixtures where an oracle exists.
The `netdev`, `filesystem`, and `uname` tests instead use goldens authored from real output, which provide weaker conformance evidence.
Filesystem byte values use `df`'s 1 KiB blocks and can differ from native filesystem statistics through block rounding.
GNU `df` exit status `1` can still provide useful rows when another mount fails.
Missing rows produce `node_filesystem_device_error = 1` without space or inode samples for that mount.
Unknown inode totals reported as `-` currently produce inode counts of `0`, retaining useful space statistics; don't interpret those zeros as measured inode availability.

A trustworthy batch can contain individual failed, truncated, or timed-out reads.
The per-read output limit is `1 MiB`, and the aggregate output limit is `8 MiB`.
Collectors report their own success separately; partial batch output doesn't necessarily fail the HTTP scrape.

## Blocks

You can use the following blocks with `prometheus.exporter.ssh`:

| Block | Description | Required |
| ----- | ----------- | -------- |
| [`auth`](#auth) | Configure named SSH credentials. | yes |
| [`diskstats`](#diskstats) | Filter disk devices. | no |
| [`filesystem`](#filesystem) | Filter mounts and filesystem types. | no |
| [`netdev`](#netdev) | Filter network devices. | no |
| [`target`](#target) | Configure a permitted SSH destination. | no |

### `auth`

Each labeled `auth` block defines credentials. Provide at least one block.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `username` | `string` | SSH account name. | | yes |
| `passphrase` | `secret` | Passphrase for an encrypted private key. | | no |
| `password` | `secret` | SSH password. | | no |
| `private_key` | `secret` | PEM or OpenSSH private key content. | | no |

Provide `private_key`, `password`, or both.
The `passphrase` argument requires `private_key`.
You can supply secrets from `local.file` with `is_secret = true` or from `remote.vault` exports.
Host key verification is required; there's no option to disable it.

### `diskstats`

The `diskstats` block filters device names with regular expressions.
A non-empty include takes precedence over the exclude.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `device_exclude` | `string` | Exclude matching disk devices. | `"^(ram\|loop\|fd\|(h\|s\|v\|xv)d[a-z]\|nvme\\d+n\\d+p)\\d+$"` | no |
| `device_include` | `string` | Include only matching disk devices. | | no |

### `filesystem`

The `filesystem` block filters mounts and filesystem types with regular expressions.
The defaults exclude pseudo filesystems and common runtime mounts.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `fs_types_exclude` | `string` | Exclude matching filesystem types. | See below. | no |
| `mount_points_exclude` | `string` | Exclude matching mount paths. | See below. | no |

The default `fs_types_exclude` expression is `^(autofs\|binfmt_misc\|bpf\|cgroup2?\|configfs\|debugfs\|devpts\|devtmpfs\|fusectl\|hugetlbfs\|iso9660\|mqueue\|nsfs\|overlay\|proc\|procfs\|pstore\|rpc_pipefs\|securityfs\|selinuxfs\|squashfs\|sysfs\|tracefs)$`.
The default `mount_points_exclude` expression is `^/(dev\|proc\|run/credentials/.+\|sys\|var/lib/docker/.+\|var/lib/containers/storage/.+)($\|/)`.
Set either expression to `""` to disable that filter.

### `netdev`

The `netdev` block filters network device names with regular expressions.
A non-empty include takes precedence over the exclude.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `device_exclude` | `string` | Exclude matching network devices. | | no |
| `device_include` | `string` | Include only matching network devices. | | no |

### `target`

Each labeled `target` block permits one SSH destination.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `address` | `string` | SSH host or host and port. | | yes |
| `auth` | `string` | Name of the credential block to use. | `"default"` | no |
| `labels` | `map(string)` | Additional labels on the exported scrape target. | | no |

The default SSH port is `22`.
Exporter routing labels, the default `job = "integrations/ssh"`, and the target's `instance` label override user-supplied labels.
Labels beginning with `__` aren't copied from the input.
Use downstream relabeling to change `job`.

## Exported fields

The following fields are exported and can be referenced by other components:

| Name | Type | Description |
| ---- | ---- | ----------- |
| `targets` | `list(map(string))` | Local exporter endpoints for each configured SSH destination. |

Each exported target includes `__param_target` and an `instance` label set to the SSH destination, not the Alloy host.
Use these exports with `prometheus.scrape`; enable clustering on `prometheus.scrape` to distribute targets.

## Component health

`prometheus.exporter.ssh` is only reported as unhealthy if given an invalid configuration.
Scrape failures affect the scrape's `up` metric rather than component health.

## Debug information

`prometheus.exporter.ssh` doesn't expose any component-specific debug information.

## Debug metrics

The following Prometheus metrics are exposed:

| Name | Type | Description |
| ---- | ---- | ----------- |
| `agentless_ssh_open_connections` | `gauge` | Current usable connections in the pool. |
| `agentless_ssh_sessions_in_use` | `gauge` | Session slots in use, including closing sessions. |
| `agentless_ssh_dials_total` | `counter` | Connection attempts, including trust checks before TCP connection. |
| `agentless_ssh_dial_errors_total` | `counter` | Failed connection attempts by fixed `reason`: `auth`, `host_key`, `timeout`, `refused`, or `other`. |
| `agentless_ssh_host_key_failures_total` | `counter` | Host key verification failures. |

These pool metrics appear on Alloy's own metrics endpoint and aggregate all targets within the component.
They don't use target, credential, auth-name, or raw-error labels, so target churn doesn't create retained per-target metric series.
A rejected attempt during backoff isn't a new dial.

Successful target scrape responses also contain the following metrics:

| Name | Type | Description |
| ---- | ---- | ----------- |
| `agentless_ssh_up` | `gauge` | `1` when the batch returns trustworthy results. |
| `agentless_ssh_scrape_duration_seconds` | `gauge` | Collection duration including the remote round trip, excluding HTTP delivery. |
| `node_scrape_collector_success` | `gauge` | `1` when the collector update succeeds without a panic; otherwise `0`. Labeled by `collector`. |
| `node_scrape_collector_duration_seconds` | `gauge` | Local collector update time only. Labeled by `collector`. |

The scrape target supplies the `instance` label on these samples.
`agentless_ssh_up = 1` doesn't imply that every collector succeeds.
On HTTP `503`, Prometheus rejects the response and records its canonical `up = 0`; don't alert on a custom `agentless_ssh_up = 0` sample, which isn't delivered on that failure path.
Use Prometheus `up` and `scrape_duration_seconds` for failed scrapes, and the pool metrics to investigate transport failures.

## Examples

### Discover and scrape hosts

This example reads a private key from a secret file and uses DNS discovery for Linux SSH hosts.
Run Alloy with experimental components enabled and clustering configured before enabling clustered scraping:


```alloy
local.file "ssh_key" {
	filename  = "<PRIVATE_KEY_FILE>"
	is_secret = true
}

discovery.dns "ssh_hosts" {
	names = ["<SSH_DNS_NAME>"]
	type  = "A"
	port  = 22
}

prometheus.exporter.ssh "hosts" {
	targets            = discovery.dns.ssh_hosts.targets
	known_hosts_files  = ["<KNOWN_HOSTS_FILE>"]
	enabled_collectors = ["cpu", "loadavg", "meminfo", "stat", "uname"]

	auth "default" {
		username    = "<SSH_USERNAME>"
		private_key = local.file.ssh_key.content
	}
}

discovery.relabel "node_job" {
	targets = prometheus.exporter.ssh.hosts.targets

	rule {
		target_label = "job"
		replacement  = "integrations/node_exporter"
	}
}

prometheus.scrape "hosts" {
	targets         = discovery.relabel.node_job.output
	scrape_interval = "15s"
	scrape_timeout  = "10s"
	forward_to      = [prometheus.remote_write.metrics.receiver]

	clustering {
		enabled = true
	}
}

prometheus.remote_write "metrics" {
	endpoint {
		url = "<REMOTE_WRITE_URL>"
	}
}
```

Replace _`<PRIVATE_KEY_FILE>`_ and _`<KNOWN_HOSTS_FILE>`_ with protected local paths, _`<SSH_USERNAME>`_ with your unprivileged account, _`<SSH_DNS_NAME>`_ with your discovery name, and _`<REMOTE_WRITE_URL>`_ with your metrics receiver URL.
The relabel rule sets `job` to `integrations/node_exporter` for Linux integration and node-mixin dashboards.
Ensure your verified host keys or host certificates match the addresses returned by discovery.
Each cluster peer needs the same target discovery, credentials, and host trust configuration.
Clustering belongs to `prometheus.scrape`, not `prometheus.exporter.ssh`.

### Read a private key from Vault

Instead of `local.file.ssh_key.content`, use a secret value from Vault:

```alloy
local.file "vault_token" {
	filename  = "<VAULT_TOKEN_FILE>"
	is_secret = true
}

remote.vault "ssh_key" {
	server = "<VAULT_SERVER_URL>"
	path   = "<VAULT_KV_PATH>"
	key    = "private_key"

	auth.token {
		token = local.file.vault_token.content
	}
}
```

Replace _`<VAULT_TOKEN_FILE>`_ with your protected token file, _`<VAULT_SERVER_URL>`_ with your Vault URL, and _`<VAULT_KV_PATH>`_ with the KV v2 secret path containing a `private_key` field.
Set the exporter's `auth` block's `private_key` argument to `remote.vault.ssh_key.data["private_key"]`.

For operational setup, refer to [Harden SSH metrics collection](../../../../configure/ssh-metrics-hardening/), [`prometheus.scrape`](../prometheus.scrape/), and [`remote.vault`](../../remote/remote.vault/).
<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`prometheus.exporter.ssh` can accept arguments from the following components:

- Components that export [Targets](../../../compatibility/#targets-exporters)

`prometheus.exporter.ssh` has exports that can be consumed by the following components:

- Components that consume [Targets](../../../compatibility/#targets-consumers)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->