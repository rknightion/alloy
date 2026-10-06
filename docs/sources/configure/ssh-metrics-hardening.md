---
canonical: https://grafana.com/docs/alloy/latest/configure/ssh-metrics-hardening/
description: Limit the risks of collecting Linux host metrics over SSH
title: Harden SSH metrics collection
---

# Harden SSH metrics collection

Use this guide to limit the risks of collecting Linux host metrics with Grafana Alloy's experimental `prometheus.exporter.ssh` component.
Alloy sends compiled-in reads over SSH without installing an exporter on the target.
Those reads aren't a sandbox for the SSH credential.

Before you begin, ensure you have the following:

- You have administrative access to configure SSH accounts and host trust through your normal change process.
- You have Linux targets with readable proc files and the commands required by your selected collectors.
- You have a protected Alloy host and a secure way to supply credentials.

## Limit the target account

Create a dedicated, unprivileged account for metrics collection.
Grant only the read access required by your enabled collectors.
Don't grant sudo, privileged group membership, or access to application secrets.
Alloy doesn't use sudo or accept user-supplied collection commands.
The account needs a working shell for the batch's `sh -s` execution; a no-login shell prevents collection.

Use the OpenSSH `restrict` option on the account's authorized public key to disable port, agent, and X11 forwarding, PTY allocation, and user SSH startup files.
For example, install a public key line through your normal account-management process:

```text
restrict ssh-ed25519 <PUBLIC_KEY_BASE64> <KEY_COMMENT>
```

Replace _`<PUBLIC_KEY_BASE64>`_ with the public key's encoded data and _`<KEY_COMMENT>`_ with an identifying comment.
Confirm your SSH server version supports `restrict` and that the effective server configuration also disables unwanted forwarding.
Where practical, limit network access to SSH from the Alloy hosts and scope the key's permitted source addresses using your SSH server policy.

{{< admonition type="warning" >}}
`restrict` doesn't disable command execution.
A forced `command=` that accepts `sh -s` accepts arbitrary shell input and isn't a security restriction for this variable batch.
Don't treat a forced command as a command allowlist or containment boundary.
A stolen SSH key, or a compromised Alloy process that holds it, can execute arbitrary commands with the account's permissions.
{{< /admonition >}}

## Verify host identity

Supply verified OpenSSH host keys through inline `known_hosts`, `known_hosts_files`, or both.
Inline content can come from a secret producer, so remotely managed pipelines don't need the collector's file-based trust argument.
The component requires host verification and doesn't offer an insecure bypass.
Obtain fingerprints through a trusted administrative channel; collecting a key from the network alone doesn't establish trust.
Match the entry to the destination Alloy uses, including discovery-returned IP addresses and non-default ports.

You can trust an SSH host certificate authority with an OpenSSH `@cert-authority` entry in the same file:

```text
@cert-authority <HOST_PATTERN> ssh-ed25519 <HOST_CA_PUBLIC_KEY_BASE64>
```

Replace _`<HOST_PATTERN>`_ with the narrow host pattern you authorize and _`<HOST_CA_PUBLIC_KEY_BASE64>`_ with your verified host CA public key.
Ensure the host certificate's principals match the configured destination.
This verifies server host certificates; the component doesn't expose a client user-certificate argument.
Protect host trust sources from modification by untrusted users and plan host-key or CA rotation with your SSH administrators.
Alloy combines inline content and files into one snapshot, polls files every `30s`, and retires pooled connections when trust changes.
Each file must be a regular file no larger than `4 MiB`; inline content has the same size cap.
A failed reload retains the old snapshot, logs a sanitized diagnostic, and increments `agentless_ssh_known_hosts_reload_failures_total`.
Alert on this counter: removing a key from an invalid replacement file doesn't revoke the old trust snapshot.
Verify that a valid replacement loads successfully before considering trust retired.
Malformed-content diagnostics don't echo the supplied trust content.

## Protect credentials and configuration

Use a protected file with `local.file` and `is_secret = true`, or a secret export from `remote.vault`, rather than embedding keys or passwords in configuration.
For complete examples, refer to the [SSH exporter reference](../../reference/components/prometheus/prometheus.exporter.ssh/#examples).
Secret typing limits accidental disclosure through Alloy configuration surfaces; it doesn't protect credentials from a compromised Alloy host or process.
Use filesystem permissions, Vault policy, and your operating system's isolation controls to protect the Alloy account.
Rotate credentials and restrict who can modify discovery, permitted targets, trust files, and the configuration.

Prefer private keys over passwords.
Host verification prevents authentication to an untrusted server, but a compromised server with a trusted host key receives the password when you authenticate.
Never share one password across targets: compromise of one trusted target could expose access to the others.
Use separate credentials with narrowly scoped permissions.

Discovery's reserved `__param_auth` label can select only a declared auth block.
Its `__param_collectors` label can select only a comma-separated subset of the effective global collector list.
An invalid selector fails that target, not the whole configuration; URL parameters can't broaden the configured selection.
Protect discovery writers because they can select among these declared credentials and permitted collectors.

The metrics handler permits only currently configured destinations.
It rejects missing, repeated, or unknown `target` parameters with HTTP `400`.
This isn't a replacement for protecting Alloy's HTTP access and configuration: an authorized configuration writer can change the destination list.
Keep the Alloy HTTP listener behind your access controls and avoid exposing it to untrusted networks.

## Control retries and account lockout

Coordinate collection with your SSH authentication and account-lockout policy.
The pool uses jittered exponential reconnect backoff from `1s` to `2m`, and authentication-failure backoff from `1m` to `30m`.
During authentication backoff, scrapes fail without a new connection attempt.
These bounds are transport defaults, not component arguments.
Backoff reduces failed-authentication floods; it doesn't guarantee that your account never locks out, especially when multiple Alloy instances share credentials.
Investigate authentication failures instead of repeatedly restarting Alloy to retry them.

The default per-target session limit is `2`, below OpenSSH's default `MaxSessions` of `10`.
The component accepts session limits from `1` to `9` and defaults to `16` concurrent dials across the pool.
Choose limits that fit your server's `MaxSessions`, `MaxStartups`, and fleet size.
Use clustered `prometheus.scrape` to distribute ownership, not duplicate independent scrapers of every target.
Keep the scrape interval at least as long as the scrape timeout; the reference example uses `15s` and `10s`.

## Monitor failures and residual risks

Alert on Prometheus's canonical `up = 0` for failed target scrapes.
Transport failures return HTTP `503`, so Prometheus rejects that response's samples.
A successful response's `agentless_ssh_up = 1` means the batch returns trustworthy results, not that all collectors succeed.
Monitor `node_scrape_collector_success` for individual collection failures and Alloy's aggregate pool metrics for dial, authentication, and host-key problems.
Refer to the [debug metrics reference](../../reference/components/prometheus/prometheus.exporter.ssh/#debug-metrics) for metric names and timing semantics.

Treat remote output as untrusted data.
Compiled reads, per-read output bounds, aggregate output bounds, timeouts, and host verification limit specific risks; they don't establish that a compromised target reports truthful metrics.
The filesystem collector uses rounded `df` block values and retains zero inode counts when an inode total is unknown.
Some collector tests use real-output goldens rather than independent node_exporter oracle output.
Refer to the [collector limitations](../../reference/components/prometheus/prometheus.exporter.ssh/#collectors) before relying on exact parity.

The exporter limits each collector's series, families, and label values, and the parsers bound retained memory fields, filesystem rows, and CPU lines.
Output-policy rejection discards that collector's buffered samples and reports `node_scrape_collector_success = 0`.
Refer to the [collector limits](../../reference/components/prometheus/prometheus.exporter.ssh/#collectors) for exact bounds and partial-output behavior.
CPU counter state expires after one hour without a successful target update, but cleanup runs only during collector updates, not on a background timer.
Limit the size and churn of discovered targets and monitor Alloy's memory use; expiry isn't a hard bound under unbounded churn.

## Next steps

Configure the [SSH exporter](../../reference/components/prometheus/prometheus.exporter.ssh/) and use its exported `instance` labels to identify remote hosts.
Relabel `job` to `integrations/node_exporter` for Linux integration and node-mixin dashboards.
Refer to [Prometheus scrape clustering](../../reference/components/prometheus/prometheus.scrape/#clustering) to distribute target ownership.
