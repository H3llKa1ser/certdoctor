# 🩺 certdoctor.sh

> A comprehensive, dependency-light **PKI / SSL certificate diagnostic tool** written in pure Bash.

`certdoctor.sh` pinpoints the most common — and many uncommon — TLS certificate problems on **live hosts** or **local files**, then reports every issue in a clean, scannable summary. Perfect for interactive debugging, scheduled monitoring, and CI/CD pipelines.

![Bash](https://img.shields.io/badge/Bash-4%2B-green)
![Dependencies](https://img.shields.io/badge/dependencies-openssl-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-orange)

---

## 📑 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Modes](#-modes)
  - [Live Host Check](#-live-host-check)
  - [Local File Check](#-local-file-check)
  - [Batch Check](#-batch-check)
- [Output Flags](#-output-flags-verbosity)
- [All Flags Reference](#-all-flags-reference)
- [Environment Variables](#-environment-variables)
- [Exit Codes](#-exit-codes)
- [What Gets Checked](#-what-gets-checked)
- [Recipes & Automation](#-recipes--automation)
- [Testing the Tool](#-testing-the-tool)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## ✨ Features

`certdoctor.sh` runs a battery of checks and surfaces every problem it finds:

| Category | Checks Performed |
|---|---|
| 📅 **Expiry** | Leaf **and every cert in the chain**; not-yet-valid detection |
| ⏳ **Validity period** | Flags certs exceeding the 398-day browser limit |
| 🏷️ **Identity** | Subject CN, SANs, hostname match, wildcard logic, IDN hints |
| 🔗 **Trust & chain** | Completeness, correct order, verification, error-code hints |
| 🔍 **Self-signed** | Detects when subject == issuer |
| 💪 **Crypto strength** | Weak RSA keys (<2048), weak signatures (SHA-1/MD5) |
| 🔑 **Cert/key match** | Modulus comparison (RSA + EC) |
| 🔒 **Key permissions** | Flags world/group-readable private keys |
| 📄 **File format** | Detects PEM / DER / PKCS#12 / PKCS#7; auto-converts DER |
| 🌐 **Live TLS** | TLS versions (flags 1.0/1.1), cipher, SNI, ALPN/HTTP-2, OCSP stapling |
| ⏰ **Environment** | NTP clock-sync status (clock-skew risk) |
| 🔌 **Connectivity** | DNS resolution + TCP reachability |

All issues are collected into a **single, scannable summary** at the end, tagged by `[host:port]` so you always know what failed where.

---

## 📦 Requirements

| Tool | Required? | Used for |
|---|---|---|
| `openssl` | ✅ Yes | All certificate operations |
| `bash` 4+ | ✅ Yes | The script itself |
| `timedatectl` | ⚪ Optional | Clock-sync check |

> No `curl`, `nc`, or `dig` needed — the tool uses Bash built-ins for DNS/TCP.

---

## 🚀 Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/<you>/<repo>/main/certdoctor.sh

# Make it executable
chmod +x certdoctor.sh

# (Optional) Install system-wide so you can run `certdoctor` anywhere
sudo cp certdoctor.sh /usr/local/bin/certdoctor
```

---

## ⚡ Quick Start

```bash
# Check a live site
./certdoctor.sh example.com

# Check local certificate files
./certdoctor.sh --file server.crt --key server.key --ca ca-bundle.crt

# Batch-check a whole fleet
./certdoctor.sh --list hosts.txt
```

---

## 🎛️ Modes

The tool runs in **one of three modes**, chosen by your arguments.

### 🌐 Live Host Check

The default mode — just pass one or more hostnames. Port defaults to `443`.

```bash
# Single host
./certdoctor.sh example.com

# Multiple hosts at once
./certdoctor.sh example.com api.example.com www.example.com

# Custom ports (append :port)
./certdoctor.sh example.com:8443

# Mix and match ports
./certdoctor.sh example.com:443 mail.example.com:465 db.example.com:5432
```

> ✅ Live mode runs **all** checks, including network-only ones (TLS versions, ciphers, SNI, ALPN, OCSP stapling).

---

### 📄 Local File Check

Inspect certificate files on disk. Triggered by `--file`.

```bash
# Inspect a certificate only
./certdoctor.sh --file server.crt
```

Add optional companions for deeper checks:

| Flag | Adds |
|---|---|
| `--key <key>` | Cert/key **match** check + **permission** check |
| `--ca <ca>` | Chain **verification** against a CA bundle |

```bash
# Cert + key → match & permission checks
./certdoctor.sh --file server.crt --key server.key

# Cert + key + CA → full local validation
./certdoctor.sh --file server.crt --key server.key --ca ca-bundle.crt

# Cert + CA only → verify trust chain
./certdoctor.sh --file server.crt --ca ca-bundle.crt
```

**Supported formats** (auto-detected): PEM, DER, PKCS#12, PKCS#7. DER is auto-converted.

```bash
./certdoctor.sh --file certificate.der    # detected & converted automatically
```

> ℹ️ File mode **skips** live-only checks (cipher, SNI, ALPN, OCSP, connectivity).

---

### 📋 Batch Check

Check many hosts from a file. Triggered by `--list`.

```bash
./certdoctor.sh --list hosts.txt
```

**File format** — one `host[:port]` per line. Blank lines and `#` comments are ignored:

```text
# hosts.txt — production fleet
example.com
api.example.com:8443

# Mail servers
mail.example.com:465
smtp.example.com:587
```

> Each host is fully diagnosed; the summary tags every issue with its `[host:port]`.

---

## 🔊 Output Flags (Verbosity)

Control **how much** is printed. Works with any mode.

| Flag | ✅ Pass | ℹ️ Info | ⚠️ Warn | ❌ Error | 📋 Summary | Best For |
|---|:---:|:---:|:---:|:---:|:---:|---|
| *(default)* | ✓ | ✓ | ✓ | ✓ | ✓ | Interactive debugging |
| `--quiet` | ✗ | ✗ | ✓ | ✓ | ✓ | Fast terminal scans |
| `--summary-only` | ✗ | ✗ | ✗ | ✗ | ✓ | Cron / CI / alerts |

```bash
# Full output (default)
./certdoctor.sh example.com

# Only show problems inline + summary
./certdoctor.sh --quiet example.com

# Suppress the scan; print only the final summary
./certdoctor.sh --summary-only example.com
```

> 💡 If both `--quiet` and `--summary-only` are passed, `--summary-only` wins.

---

## 📋 All Flags Reference

| Flag | Argument | Mode | Description |
|---|---|---|---|
| `--file` | `<cert>` | File | Certificate to inspect (PEM/DER) |
| `--key` | `<key>` | File | Private key → enables match + permission checks |
| `--ca` | `<ca>` | File | CA bundle to verify the chain against |
| `--list` | `<file>` | Batch | File of hosts, one `host[:port]` per line |
| `--quiet` | — | Any | Show only warnings/errors inline + summary |
| `--summary-only` | — | Any | Show only the final summary block |
| `-h`, `--help` | — | — | Print help and exit |

---

## 🌱 Environment Variables

Tune thresholds **without editing the script** by prefixing the command.

| Variable | Default | Meaning |
|---|---|---|
| `WARN_DAYS` | `30` | ⚠️ Warn if a cert expires within N days |
| `CRIT_DAYS` | `7` | ❌ Critical if a cert expires within N days |
| `TIMEOUT` | `10` | Per-connection timeout (seconds) |

```bash
# Warn earlier — 60 days out
WARN_DAYS=60 ./certdoctor.sh example.com

# Stricter windows
WARN_DAYS=45 CRIT_DAYS=14 ./certdoctor.sh --list hosts.txt

# Extend timeout for a slow host
TIMEOUT=30 ./certdoctor.sh slow-host.example.com

# Combine with flags
WARN_DAYS=60 ./certdoctor.sh --summary-only --list fleet.txt
```

---

## 🚦 Exit Codes

The exit code reflects the **worst** issue found — ideal for scripting and CI gates.

| Code | Meaning | When |
|:---:|---|---|
| `0` | ✅ All passed | No warnings or errors |
| `1` | ⚠️ Warnings | Warnings only, no critical errors |
| `2` | ❌ Critical | At least one critical error |
| `3` | 🚫 Usage error | Bad args, missing file, or `openssl` missing |

```bash
./certdoctor.sh example.com
echo "Exit code: $?"

# Use in a conditional
if ./certdoctor.sh --summary-only example.com; then
  echo "Certs healthy"
else
  echo "Problems detected (exit $?)"
fi
```

---

## 🔬 What Gets Checked

| Check | Live | Batch | File |
|---|:---:|:---:|:---:|
| DNS resolution | ✅ | ✅ | — |
| TCP reachability | ✅ | ✅ | — |
| Expiry (full chain) | ✅ | ✅ | ✅¹ |
| Validity period (398-day) | ✅ | ✅ | ✅ |
| Subject / SAN / hostname match | ✅ | ✅ | ✅² |
| Self-signed detection | ✅ | ✅ | ✅ |
| Chain completeness & order | ✅ | ✅ | — |
| Chain verification | ✅ | ✅ | ✅³ |
| Key strength & signature | ✅ | ✅ | ✅ |
| Cert/key match | — | — | ✅⁴ |
| Key permissions | — | — | ✅⁴ |
| File format detection | — | — | ✅ |
| TLS versions / cipher | ✅ | ✅ | — |
| SNI behavior | ✅ | ✅ | — |
| ALPN / HTTP-2 | ✅ | ✅ | — |
| OCSP stapling | ✅ | ✅ | — |
| Clock sync | ✅ | ✅ | — |

> ¹ Cert only (no live chain) ² Skipped (no host context) ³ Requires `--ca` ⁴ Requires `--key`

---

## 🍳 Recipes & Automation

### Daily cron — email only on problems

```bash
# /etc/cron.d/certcheck — runs at 6 AM daily
0 6 * * * root /usr/local/bin/certdoctor --summary-only --list /etc/cert-hosts.txt \
  || mail -s "⚠️ Certificate issues detected" ops@example.com
```

> The `||` fires the email only when the exit code is non-zero.

### CI/CD gate — fail only on critical

```bash
./certdoctor.sh --summary-only api.staging.example.com
code=$?
[ "$code" -ge 2 ] && { echo "Critical cert issue — failing build"; exit 1; }
```

### Post the summary to Slack

```bash
./certdoctor.sh --summary-only --list hosts.txt \
  | curl -s -X POST "$SLACK_WEBHOOK" \
      --data-urlencode "payload={\"text\":\"$(cat -)\"}"
```

> Colors auto-disable when piped, so Slack/email get clean plain text.

### Verify a new cert before deploying

```bash
./certdoctor.sh --file new-server.crt --key new-server.key --ca chain.crt
# Exit 0 = safe to deploy
```

### Fleet health snapshot with a wider warning window

```bash
WARN_DAYS=45 ./certdoctor.sh --summary-only --list fleet.txt
```

---

## 🧪 Testing the Tool

Use the public [**badssl.com**](https://badssl.com) endpoints to confirm the tool catches problems correctly:

```bash
./certdoctor.sh expired.badssl.com            # → exit 2 (expired)
./certdoctor.sh wrong.host.badssl.com         # → exit 2 (name mismatch)
./certdoctor.sh self-signed.badssl.com        # → exit 2 (self-signed)
./certdoctor.sh untrusted-root.badssl.com     # → exit 2 (untrusted CA)
./certdoctor.sh incomplete-chain.badssl.com   # → exit 1 (incomplete chain)
./certdoctor.sh badssl.com                     # → exit 0 (control — healthy)
```

Verify exit codes for automation:

```bash
./certdoctor.sh expired.badssl.com > /dev/null 2>&1; echo "Exit: $?"   # → 2
./certdoctor.sh badssl.com         > /dev/null 2>&1; echo "Exit: $?"   # → 0
```

---

## 🛠️ Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Missing required tool: openssl` | `openssl` not installed | `apt install openssl` / `brew install openssl` |
| `Cannot reach host:port (TCP)` | Firewall / wrong port / host down | Verify connectivity and port |
| `TLS handshake failed` | Protocol/cipher mismatch or non-TLS port | Confirm the port speaks TLS |
| Colors look garbled in a log file | Output redirected to a non-terminal | Expected — colors auto-disable when piped |
| Clock check says "unknown" | `timedatectl` not present | Optional check; safe to ignore |

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

**Found it useful?** ⭐ Star the repo and share it with your team!

</div>
