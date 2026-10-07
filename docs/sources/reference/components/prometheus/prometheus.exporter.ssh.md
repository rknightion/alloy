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

Before you begin, provide an SSH account, credentials, and verified OpenSSH `known_hosts` content.
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
| `known_hosts` | `secret` or `string` | Inline verified OpenSSH host key content. | | no |
| `known_hosts_files` | `list(string)` | Paths to verified OpenSSH host key files. | | no |
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
Discovery targets use `address` or `__address__` for the SSH destination.
The reserved `__param_auth` label selects an already declared `auth` block; an absent or empty value selects `default`.
The ordinary `auth` discovery label isn't supported.
The reserved `__param_collectors` label selects a comma-separated subset of the effective global collector list, without spaces or duplicate names.
An absent or empty value selects the whole effective global list.
An undefined auth name or invalid collector selector fails only that target's scrape with HTTP `503`; other targets remain usable.
URL query parameters can't broaden this selection: supplied `auth` and `collectors` parameters must exactly match the configured selection or the handler returns HTTP `400`.

Provide `known_hosts`, `known_hosts_files`, or both.
The inline argument accepts a string or a secret-producing component's value (`OptionalSecret` in the implementation).
Alloy combines inline content with all configured files into one trust snapshot.
Inline content and each file have a `4 MiB` cap, and files must be regular files.
Alloy polls files every `30s` and retires pooled connections when the trust snapshot changes, so subsequent connections verify against the new snapshot.
Updates to inline content also replace trust through component configuration updates.
A failed file reload retains the previous snapshot and increments `agentless_ssh_known_hosts_reload_failures_total`.
Malformed-content diagnostics don't include the supplied host key content.

An empty `enabled_collectors` list enables the 28 default collectors: `arp`, `conntrack`, `cpu`, `diskstats`, `dmi`, `entropy`, `filefd`, `filesystem`, `ipvs`, `loadavg`, `mdadm`, `meminfo`, `netclass`, `netdev`, `netstat`, `nfs`, `nfsd`, `os`, `pressure`, `schedstat`, `selinux`, `sockstat`, `softnet`, `stat`, `udp_queues`, `uname`, `vmstat`, and `zfs`.
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
Collectors with listing reads can request a second execution for fixed attribute files derived from validated names.
Expanded reads are bounded to `1024` per collector and `4096` per scrape.
Exceeding either cap rejects the affected expansion without reading or emitting a truncated subset.
You can't supply custom commands.

| Name | Fixed reads | Metrics |
| ---- | ----------- | ------- |
| `arp` | `/proc/net/arp`. | ARP entry counts by device (`node_arp_entries`). |
| `conntrack` | `/proc/sys/net/netfilter/nf_conntrack_count`, `/proc/sys/net/netfilter/nf_conntrack_max`, and `/proc/net/stat/nf_conntrack`. | Connection tracking entry, limit, and statistics gauges (`node_nf_conntrack_*`). |
| `cpu` | `/proc/stat`. | CPU time counters (`node_cpu_seconds_total`). |
| `diskstats` | `/proc/diskstats`. | Disk I/O counters and gauges (`node_disk_*`). |
| `dmi` | Twenty fixed files under `/sys/class/dmi/id`: `bios_date`, `bios_release`, `bios_vendor`, `bios_version`, `board_asset_tag`, `board_name`, `board_serial`, `board_vendor`, `board_version`, `chassis_asset_tag`, `chassis_serial`, `chassis_vendor`, `chassis_version`, `product_family`, `product_name`, `product_serial`, `product_sku`, `product_uuid`, `product_version`, and `sys_vendor`. | DMI identity labels (`node_dmi_info`), with `sys_vendor` exported as `system_vendor`. Unavailable or unreadable attributes are omitted. |
| `entropy` | `/proc/sys/kernel/random/entropy_avail` and `/proc/sys/kernel/random/poolsize`. | Entropy gauges (`node_entropy_available_bits` and `node_entropy_pool_size_bits`). |
| `filefd` | `/proc/sys/fs/file-nr`. | File descriptor gauges (`node_filefd_allocated` and `node_filefd_maximum`). |
| `filesystem` | `env LC_ALL=C df -akPT`, `env LC_ALL=C df -aiPT`, and `/proc/self/mounts`. | Space, inode, read-only, and device-error gauges (`node_filesystem_*`). |
| `ipvs` | `/proc/net/ip_vs_stats` and `/proc/net/ip_vs`. | IP virtual server traffic counters and backend connection and weight gauges (`node_ipvs_*`). |
| `loadavg` | `/proc/loadavg`. | Load averages (`node_load1`, `node_load5`, and `node_load15`). |
| `mdadm` | `/proc/mdstat`. | Software RAID state, disk counts, required disks, blocks, and synced blocks (`node_md_*`). |
| `meminfo` | `/proc/meminfo`. | Memory gauges (`node_memory_*`). |
| `netclass` | `ls -1 /sys/class/net`, then 22 fixed attribute files per valid interface. | Sysfs network properties (`node_network_*`), including interface identity and state. Netlink statistics aren't collected. |
| `netdev` | `/proc/net/dev`. | Network receive and transmit counters (`node_network_*`). |
| `netstat` | `/proc/net/snmp`, `/proc/net/snmp6`, and `/proc/net/netstat`. | Selected protocol statistics (`node_netstat_*`). |
| `nfs` | `/proc/net/rpc/nfs`. | NFS client network, RPC, and procedure counters (`node_nfs_*`). |
| `nfsd` | `/proc/net/rpc/nfsd`. | NFS server reply cache, file handle, I/O, thread, read-ahead, network, RPC, and procedure metrics (`node_nfsd_*`). |
| `os` | `/etc/os-release`, with `/usr/lib/os-release` as fallback. | OS identity (`node_os_info`). |
| `pressure` | `/proc/pressure/cpu`, `/proc/pressure/memory`, `/proc/pressure/io`, and `/proc/pressure/irq`. | CPU, memory, and I/O waiting time counters and memory and I/O stalled time counters (`node_pressure_*_seconds_total`). CPU full and IRQ statistics aren't exported. |
| `schedstat` | `/proc/schedstat`. | Per-CPU running and waiting time counters and timeslice counters (`node_schedstat_*`). |
| `selinux` | `/proc/self/mountinfo`, `/sys/fs/selinux/enforce`, and `/etc/selinux/config`. | SELinux enabled, configured mode, and current mode gauges (`node_selinux_*`). Reads mirror the fixed mount detection, config, and enforce inputs; nonstandard mount paths don't change the reads. |
| `sockstat` | `/proc/net/sockstat`, `/proc/net/sockstat6`, and `getconf PAGESIZE`. | Socket usage and memory gauges (`node_sockstat_*`), using the target's page size for byte values. |
| `softnet` | `/proc/net/softnet_stat`. | Per-CPU packet processing counters and backlog gauges (`node_softnet_*`). |
| `stat` | `/proc/stat`. | Boot time, context switches, interrupts, forks, and running or blocked processes. |
| `udp_queues` | `/proc/net/udp` and `/proc/net/udp6`. | Aggregated transmit and receive queue memory gauges by IP version (`node_udp_queues`). |
| `uname` | `uname -s`, `uname -n`, `uname -r`, `uname -v`, `uname -m`, and `/proc/sys/kernel/domainname`. | Kernel and host identity (`node_uname_info`). |
| `vmstat` | `/proc/vmstat`. | Selected virtual memory statistics (`node_vmstat_*`), with fields matching `^(oom_kill\|pgpg\|pswp\|pg.*fault).*`. |
| `zfs` | Eleven fixed files under `/proc/spl/kstat/zfs`: `abdstats`, `arcstats`, `dbufstats`, `dmu_tx`, `dnodestats`, `fm`, `vdev_cache_stats`, `vdev_mirror_stats`, `xuio_stats`, `zfetchstats`, and `zil`. | Numeric kstat families (`node_zfs_*`). Pool and dataset families (`node_zfs_zpool_*` and `node_zfs_zpool_dataset_*`), including pool state, are omitted. |

The `netclass` collector reads these fixed attributes under each validated `/sys/class/net/<interface>/` path: `addr_assign_type`, `carrier`, `carrier_changes`, `carrier_up_count`, `carrier_down_count`, `dev_id`, `dormant`, `flags`, `ifindex`, `iflink`, `link_mode`, `mtu`, `name_assign_type`, `netdev_group`, `speed`, `tx_queue_len`, `type`, `address`, `broadcast`, `duplex`, `operstate`, and `ifalias`.
Forty-six interfaces fit the `1024` expanded-read cap (`1012` attribute files, or `1013` reads including the listing); forty-seven don't (`1034` attribute files, or `1035` reads including the listing).
Too many interfaces fail the collector atomically, without attribute reads or data samples.
Invalid names and the `bonding_masters` control file are skipped.
Failed attribute reads are omitted, so an unreadable speed file doesn't fail other interface properties.
Malformed attribute values fail the collector atomically.

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

Each collector can emit at most `20,000` series and `500` metric families per scrape, with at most `4096` bytes per label value.
Exceeding these limits or ending the scrape context sets `node_scrape_collector_success` to `0` and discards that collector's buffered samples.
An ordinary collector error or panic also reports success `0`, but retains valid partial output that passes these checks.
The `meminfo` parser limits retained fields to `500` before metric creation.
The filesystem parser limits mounts to `10,000` and each `df` output to `10,000` data rows.
The CPU parser accepts at most `8192` CPU lines, counting the aggregate line and duplicate lines, and CPU IDs up to `65535`.
CPU counter state expires after one hour without a successful update for that target.
Expiry runs during collector `Update` calls, including failed reads of other targets, not on a background timer; stopping all scrapes stops expiry.

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
Prefer private keys over passwords: a compromised but trusted SSH server receives any password you use to authenticate.
Never share one password across targets.

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

The default `fs_types_exclude` expression is `^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$`.
The default `mount_points_exclude` expression is `^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`.
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

Each exported target includes `__param_target`, `__param_auth`, and `__param_collectors`, plus an `instance` label set to the SSH destination, not the Alloy host.
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
| `agentless_ssh_known_hosts_reload_failures_total` | `counter` | Failed trust reloads that retain the previous snapshot. |

These pool metrics appear on Alloy's own metrics endpoint and aggregate all targets within the component.
They don't use target, credential, auth-name, or raw-error labels, so target churn doesn't create retained per-target metric series.
A rejected attempt during backoff isn't a new dial.

Successful target scrape responses also contain the following metrics:

| Name | Type | Description |
| ---- | ---- | ----------- |
| `agentless_ssh_up` | `gauge` | `1` when the batch returns trustworthy results. |
| `agentless_ssh_scrape_duration_seconds` | `gauge` | Collection duration including the remote round trip, excluding HTTP delivery. |
| `node_scrape_collector_success` | `gauge` | `1` when the update succeeds without a panic, output-policy rejection, or expired scrape context; otherwise `0`. Labeled by `collector`. |
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

### Use a remotely managed pipeline

For a remotely managed configuration, such as a Grafana Cloud Fleet Management pipeline, supply credentials through secret producers on each Alloy host.
This example uses inline trust content and doesn't require the collector's `known_hosts_files` API:

```alloy
local.file "ssh_key" {
	filename  = "<PRIVATE_KEY_FILE>"
	is_secret = true
}

local.file "ssh_trust" {
	filename  = "<VERIFIED_HOST_KEYS_FILE>"
	is_secret = true
}

local.file "metrics_password" {
	filename  = "<REMOTE_WRITE_PASSWORD_FILE>"
	is_secret = true
}

prometheus.exporter.ssh "remote_hosts" {
	known_hosts        = local.file.ssh_trust.content
	enabled_collectors = ["cpu", "meminfo", "uname"]
	targets = [{
		"__address__"        = "<SSH_HOST>",
		"__param_auth"       = "metrics",
		"__param_collectors" = "cpu,meminfo",
	}]

	auth "metrics" {
		username    = "<SSH_USERNAME>"
		private_key = local.file.ssh_key.content
	}
}

prometheus.scrape "remote_hosts" {
	targets    = prometheus.exporter.ssh.remote_hosts.targets
	forward_to = [prometheus.remote_write.metrics.receiver]
}

prometheus.remote_write "metrics" {
	endpoint {
		url = "<REMOTE_WRITE_URL>"

		basic_auth {
			username = "<REMOTE_WRITE_USERNAME>"
			password = local.file.metrics_password.content
		}
	}
}
```

Replace _`<PRIVATE_KEY_FILE>`_, _`<VERIFIED_HOST_KEYS_FILE>`_, and _`<REMOTE_WRITE_PASSWORD_FILE>`_ with protected files on each Alloy host.
Replace _`<SSH_HOST>`_ and _`<SSH_USERNAME>`_ with your permitted Linux destination and unprivileged account.
Replace _`<REMOTE_WRITE_URL>`_ and _`<REMOTE_WRITE_USERNAME>`_ with your metrics receiver's URL and account identifier.
Enable experimental components on each Alloy host.
Remote configuration distribution doesn't provision these files or verify metrics ingestion; verify delivery separately in your environment.
You can also use Vault secret exports instead of local secret files, as in the following example.

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

	auth.token {
		token = local.file.vault_token.content
	}
}
```

Replace _`<VAULT_TOKEN_FILE>`_ with your protected token file, _`<VAULT_SERVER_URL>`_ with your Vault URL, and _`<VAULT_KV_PATH>`_ with the KV v2 mount and secret path in `<MOUNT>/<SECRET_PATH>` form, containing a `private_key` field.
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