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
    private_key = <PRIVATE_KEY_SECRET>
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
Timeouts must be positive, and `max_sessions_per_target` must be between `1` and `9`.

The metrics handler accepts only configured destinations through its `target` query parameter.
Unknown targets return HTTP `400`, and transport failures return HTTP `503`.
When a scrape includes `X-Prometheus-Scrape-Timeout-Seconds`, the batch deadline subtracts `500ms` from that value and is capped by `timeout`.

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
| `device_exclude` | `string` | Exclude matching disk devices. | `"^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$"` | no |
| `device_include` | `string` | Include only matching disk devices. | | no |

### `filesystem`

The `filesystem` block filters mounts and filesystem types with regular expressions.
The defaults exclude pseudo filesystems and common runtime mounts.

| Name | Type | Description | Default | Required |
| ---- | ---- | ----------- | ------- | -------- |
| `fs_types_exclude` | `string` | Exclude matching filesystem types. | | no |
| `mount_points_exclude` | `string` | Exclude matching mount paths. | | no |

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
Exporter routing labels and the target's `instance` label override user-supplied labels.

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
| `agentless_ssh_host_key_failures_total` | `counter` | Handshakes rejected by host key verification. |

## Example

This example reads a private key from a secret file and scrapes a Linux host:

```alloy
local.file "ssh_key" {
  filename  = "/etc/alloy/ssh/id_ed25519"
  is_secret = true
}

prometheus.exporter.ssh "hosts" {
  known_hosts_files   = ["/etc/alloy/ssh/known_hosts"]
  enabled_collectors = ["cpu", "loadavg", "meminfo", "stat", "uname"]

  auth "default" {
    username    = "metrics"
    private_key = local.file.ssh_key.content
  }

  target "linux" {
    address = "linux.example.com:22"
  }
}

prometheus.scrape "hosts" {
  targets    = prometheus.exporter.ssh.hosts.targets
  forward_to = []

  clustering {
    enabled = true
  }
}
```

Replace the example file paths, SSH account, and host with your environment's values.
Set `forward_to` to your metrics receiver to send the scraped metrics.
For scrape configuration, refer to [`prometheus.scrape`](../prometheus.scrape/).
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