# Banhammer

A single-binary, low-footprint intrusion-prevention daemon — `fail2ban` without the Python
runtime or the `.conf`/`.local` inheritance maze.

Tail logs (text or JSON) from files or sockets, match offending lines, extract the offender's IP,
and ban it with `iptables`/`nft`/`ipset`/any command when it shows up **X times in Y minutes** —
then unban it **Z minutes** later.

```yaml
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
```
> 5 hits in 10 minutes ⇒ `DROP` for 1 hour. That's the whole config.

**Status: v1 implementation complete.** Production-ready, fully tested with zero-allocation fast paths, sliding-window rate tracking, robust persistent state, and systemd sandboxing. See [PROJECT.md](./PROJECT.md) for full architectural specifications.

---

## Features

* **High Performance:** Over 6 million lines/sec throughput on text logs and over 1 million lines/sec on JSON logs. Zero heap allocations on non-matching log paths.
* **Low Memory Footprint:** Flat O(threshold) memory per tracked IP (~120 B/IP); strictly under 20 MB RSS in production.
* **Text and JSON Log Decoding:** Global regex with the `<IP>` macro on raw text lines, or nested dotted-field paths (`request.remote_ip`) with fast scanning on structured JSON.
* **Flexible Backends:** Built-in support for `iptables` (with automatic IPv4/IPv6 segregation), `nftables`, `ipset` (scales to 100k+ bans), and custom shell command templates (`cmd`).
* **Resilient Persistence:** Survives daemon restarts without replay loops; persists active bans and source read offsets atomically.
* **Built-in CLI Tooling:** Interactive rule tester (`test`), strict config validator (`check`), live status query (`status`), manual ban/unban commands, and dynamic configuration reloads.

---

## Installation & Quickstart

### 1. Build from Source

Banhammer requires Go 1.22+ and has zero C/C++ runtime dependencies.

```bash
# Clone and build
git clone https://github.com/roigabay/banhammer.git
cd banhammer
go build -o banhammer ./cmd/banhammer

# Verify binary
./banhammer --help
```

### 2. Validate Configuration

Verify your configuration syntax, inspect expanded `<IP>` macros, and view merged defaults:

```bash
./banhammer check -c config.example.yaml
```

### 3. Test Rules Interactively

Test your regexes and simulate sliding-window ban timelines against real or sample log files before deploying:

```bash
./banhammer test -c config.example.yaml -m sshd -f /var/log/auth.log
```

### 4. Run the Daemon

```bash
# Run in foreground with dry-run mode (logs actions without altering firewall)
./banhammer run -c config.example.yaml --dry-run

# Run in production
sudo ./banhammer run -c /etc/banhammer/config.yaml
```

---

## Configuration

Banhammer uses a single, declarative YAML configuration file. Default settings apply globally and can be overridden on a per-monitor basis. See [config.example.yaml](./config.example.yaml) for a complete reference.

```yaml
state_dir: /var/lib/banhammer
log_format: text
queue_size: 8192
allow_local: true
allowlist:
  - 127.0.0.1/8
  - ::1/128
  - 10.0.0.0/8
  - 192.168.0.0/16

defaults:
  threshold: 5          # hits before ban
  window: 10m           # sliding window
  bantime: 1h           # ban duration
  bantime_factor: 1     # exponential escalation multiplier
  bantime_max: 168h     # max ban duration
  find_history: 24h     # offense history retention
  max_tracked: 100000   # LRU cap for tracked IPs
  action: iptables      # iptables | nft | ipset | cmd

monitors:
  sshd:
    file: /var/log/auth.log
    match:
      - "Failed password .* from <IP>"
      - "Invalid user .* from <IP>"
    ignore: "from <IP> port .* ssh2: RSA"

  caddy:
    file: /var/log/caddy/access.log
    format: json
    match:
      status: "^(401|403|404)$"
      request.uri: "\\.(env|git|ini|php)$"
    ip_field: request.remote_ip
    threshold: 20
    window: 1m
    bantime: 24h

  syslog-remote:
    listen: udp://0.0.0.0:5140
    strip_syslog: true
    match: "authentication failure.*rhost=<IP>"
    action: ipset
```

---

## CLI Command Guide

All CLI management commands communicate with the running daemon over its Unix domain control socket (`/run/banhammer.sock` when root, or `<state_dir>/control.sock`).

### `run` — Start Daemon
Starts the intrusion prevention daemon, ingestion sources, matching workers, aggregator, and action executor.

```bash
banhammer run -c /etc/banhammer/config.yaml [flags]
```
* `-c, --config`: Path to configuration file (default: `/etc/banhammer/config.yaml` or `./config.yaml`).
* `--dry-run`: Evaluate logs and report bans without executing firewall changes.
* `--state-dir`: Override persistent state directory.
* `--log-format`: Log output format (`text` or `json`).
* `--log-level`: Logging verbosity (`debug`, `info`, `warn`, `error`).

### `check` — Validate Configuration
Strictly validates YAML syntax, monitors, source definitions, regex compilation, and macro expansion. Fails loudly on unknown keys.

```bash
banhammer check -c /etc/banhammer/config.yaml
```

### `test` — Rule & Timeline Simulator
The regex authoring tool: simulates log parsing line-by-line against sample files, displaying per-line verdicts (`MATCH`, `NO_MATCH`, `IGNORED`, `NO_IP`), extracted IPs, and timestamps of triggered bans.

```bash
banhammer test -c /etc/banhammer/config.yaml -m sshd -f /var/log/auth.log
```
* `-m, --monitor`: Name of the monitor to test.
* `-f, --file`: Path to sample log file.

### `status` — Live Daemon Telemetry
Queries the active daemon for uptime, pipeline metrics (lines read, dropped, matched), monitor status, tracked IPs, and the list of active bans.

```bash
banhammer status
banhammer status --json
```

### `ban` — Manually Ban an IP
Manually adds an IP address to the firewall ban list for a designated period.

```bash
banhammer ban 198.51.100.25
banhammer ban 203.0.113.50 --time 24h --monitor sshd
```

### `unban` — Lift Bans
Removes an active firewall ban for an IP, or flushes all active bans.

```bash
banhammer unban 198.51.100.25
banhammer unban --all
```

### `reload` — Dynamic Configuration Reload
Instructs the running daemon to re-read its configuration file and recompile rule sets without dropping active state or restarting.

```bash
banhammer reload
```

---

## Fail2ban Migration Guide

Banhammer replaces Fail2ban's multi-file configuration maze (`jail.conf`, `jail.local`, `filter.d/*.conf`, `action.d/*.conf`) with a clean, single-file YAML format, while providing equivalent or superior functionality.

### Directive Comparison

| Fail2ban Directive / Concept | Banhammer Equivalent | Notes |
|---|---|---|
| `[jail-name]` | `monitors.<name>` | Each monitor represents an independent log ingestion and rule set. |
| `logpath = /var/log/auth.log` | `file: /var/log/auth.log` | Supports glob expressions (e.g. `/var/log/nginx/*access.log`). |
| `backend = systemd` / socket | `listen: udp://...` or `stdin: true` | Listen directly on UDP/TCP/Unix sockets, or pipe via `journalctl -f \| banhammer run`. |
| `maxretry = 5` | `threshold: 5` | Number of offenses within the window before banning. |
| `findtime = 10m` | `window: 10m` | Sliding-window evaluation duration (e.g., `30s`, `10m`, `24h`). |
| `bantime = 1h` | `bantime: 1h` | Base ban duration. |
| `bantime.increment = true` | `bantime_factor: 2` | Exponential backoff multiplier on repeat offenses. |
| `bantime.maxtime = 1w` | `bantime_max: 168h` | Maximum escalated ban duration ceiling. |
| `ignoreip = 127.0.0.1/8` | `allowlist: [...]` | List of CIDR blocks or IPs that are never banned. |
| Automatic loopback whitelist | `allow_local: true` | Automatically whitelists loopback and local host interface IPs. |
| `failregex = ...` | `match: "..."` or `match: [...]` | String or list of regex patterns (OR semantics). Uses Go RE2 (linear time). |
| `ignoreregex = ...` | `ignore: "..."` or `ignore: [...]` | Patterns that veto a match when triggered. |
| `<HOST>` / `<IP>` | `<IP>` or `<HOST>` | Macro expanding to robust IPv4 and IPv6 capture regex. |
| JSON log filtering | `format: json` + `match: {field: regex}` | Native JSON decoding with dotted field paths (AND semantics). No python regex hacks. |
| `banaction = iptables-multiport` | `action: iptables` | Built-in `iptables` backend handles chains and IPv4/IPv6 automatically. |
| `banaction = nftables-multiport` | `action: nft` | Native `nftables` tables and sets with kernel timeouts. |
| `banaction = ipset` | `action: ipset` | High-performance hash sets with O(1) matching; handles 100k+ bans. |
| Custom action scripts | `action: cmd` | Command templates with `{ip}`, `{monitor}`, `{bantime}`, `{count}`. |

### Migration Example: SSH Jail

#### Fail2ban (`/etc/fail2ban/jail.local` & `/etc/fail2ban/filter.d/sshd.conf`)
```ini
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8 10.0.0.0/8
failregex = ^%(__prefix_line)sFailed \S+ for .* from <HOST>(?: port \d+)?(?: ssh\d*)?$
            ^%(__prefix_line)s[iI]nvalid user .* from <HOST>(?: port \d+)?(?: ssh\d*)?$
```

#### Banhammer (`/etc/banhammer/config.yaml`)
```yaml
allowlist: [127.0.0.1/8, 10.0.0.0/8]

monitors:
  sshd:
    file: /var/log/auth.log
    threshold: 5
    window: 10m
    bantime: 1h
    match:
      - "Failed .* for .* from <IP>"
      - "Invalid user .* from <IP>"
```

---

## Systemd Service Deployment

A hardened systemd unit file is included in [`banhammer.service`](./banhammer.service) featuring strict sandboxing, unprivileged execution options, read-only system protection, and capabilities management.

### Deployment Steps

1. **Build and install the binary:**
   ```bash
   go build -ldflags="-s -w" -o /usr/bin/banhammer ./cmd/banhammer
   chmod 755 /usr/bin/banhammer
   ```

2. **Install configuration:**
   ```bash
   mkdir -p /etc/banhammer
   cp config.example.yaml /etc/banhammer/config.yaml
   chmod 644 /etc/banhammer/config.yaml
   ```

3. **Install and activate the systemd unit:**
   ```bash
   cp banhammer.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now banhammer
   ```

4. **Verify operation:**
   ```bash
   systemctl status banhammer
   banhammer status
   ```

5. **Reload configuration dynamically:**
   ```bash
   # Both systemctl reload and banhammer reload send SIGHUP / IPC reload
   systemctl reload banhammer
   # OR
   banhammer reload
   ```

---

## Performance & Verification

Banhammer includes comprehensive benchmarks measuring throughput across synthetic 1M-line corpora:

```bash
# Run all unit and integration tests
go test ./...

# Run pipeline benchmark suite
go test -bench=BenchmarkPipeline -benchtime=1s ./test
```

### Typical Benchmark Results
* **`auth.log` throughput:** ~6,000,000 lines/sec (0 B/op, 0 allocs/op)
* **`auth.log` non-matching reject path:** ~26,000,000 lines/sec (0 B/op, 0 allocs/op)
* **JSON access log throughput:** ~1,000,000 lines/sec
* **Idle memory usage:** < 10 MB RSS

---

## License

Apache 2.0. See LICENSE for details.
