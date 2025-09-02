# SockProbe - Safe SOCKS Proxy Scanner

A safe, authorized-scopes-only SOCKS proxy scanner written in Rust with strict guardrails.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/your-username/sockprobe)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.65%2B-orange)](https://www.rust-lang.org/)

## Features

- **Input**: IP, IP range (start-end), or CIDR; ports or ranges
- **Detection**: 
  - SOCKS5 (no-auth and/or username/password)
  - Optional SOCKS4/4a (requires verify target)
- **Safety**:
  - Allowlist-only by default (RFC1918)
  - Do-not-scan list
  - Scan cap (4096 sockets)
  - Opt-in loopback scanning
  - No brute forcing
- **Output**: JSONL results and live progress
- **Interactive**: Progress bar, counters; safe defaults to avoid noisy behavior
- **Blocklist**: User-managed blocklist file (YAML) for restricted ranges
- **IPv6**: Support (with equal guardrails)
- **Audit log**: Attestation and parameters in run manifest
- **Scheduler**: Optional cron-like runner (planned)

## Use Cases

   - 🔍 Network Auditing: Identify SOCKS proxies in authorized networks
   - 🛡️ Security Assessments: Verify proxy configurations and access controls
   - 🏢 Corporate Environments: Scan authorized infrastructure safely
   - 🔬 Research: Study proxy deployment patterns with proper authorization
   - 🌐 Public Networks: Scan for open proxies with caution
   - 🗺️ Threat Map: Visualize proxy deployment patterns and potential security risks
   - 🔍 Asset Discovery: Identify and map proxy infrastructure within authorized networks


## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/muhiminulhasan/sockprobe.git
cd sockprobe

# Build the project
cargo build --release

# The binary will be located at target/release/sockprobe
```

## Usage Examples

### Authorized local scan (private ranges only by default):
```bash
sockprobe --targets 192.168.1.0/24 --ports 1080 --attest "authorized to test 192.168.1.0/24" --out results.jsonl
```

### Check username/password only on your lab subnet:
```bash
sockprobe --targets 10.10.10.0/24 --ports 1080 \
  --user alice --password s3cret --attest "authorized for 10.10.10.0/24" --out results.jsonl
```

### Enable SOCKS4/4a detection by requesting a CONNECT to your own test host (must be allowed):
```bash
sockprobe --targets 10.0.0.0/24 --ports 1080 \
  --verify 10.0.0.99:80 --attest "authorized for 10.0.0.0/24" --out results.jsonl
```

### Using a custom blocklist:
```bash
sockprobe --targets 192.168.1.0/24 --ports 1080 \
  --attest "authorized to test 192.168.1.0/24" --out results.jsonl \
  --blocklist-file blocklist.yaml
```

### Scan specific IP range with multiple ports:
```bash
sockprobe --targets 192.168.1.10-192.168.1.50 --ports 1080,1081,8080 \
  --attest "authorized to test 192.168.1.10-192.168.1.50" --out results.jsonl
```

### Scan with custom allowlist for public IPs:
```bash
sockprobe --targets 203.0.113.0/24 --ports 1080 \
  --attest "authorized to test 203.0.113.0/24" --out results.jsonl \
  --enable-public --allowlist 203.0.113.0/24
```

### Scan with reduced concurrency and custom timeout:
```bash
sockprobe --targets 192.168.1.0/24 --ports 1080 \
  --attest "authorized to test 192.168.1.0/24" --out results.jsonl \
  --concurrency 64 --connect-timeout 5.0
```

## Hard Guardrails

- **Default allowlist**: RFC1918 (10/8, 172.16/12, 192.168/16). Anything else is blocked unless you pass `--enable-public` AND the scope is on your explicit `--allowlist`.
- **Do-not-scan**: IANA special-use blocks (loopback, link-local, multicast, documentation, etc.) always blocked.
- **Loopback** (127.0.0.0/8) blocked by default; enable with `--allow-loopback` if you're testing on localhost.
- **No brute forcing**: Will only test credentials you supply.
- **Scan cap**: 4096 target sockets per run, unless you explicitly raise with `--max-targets` and a clear attestation.

## Ethics and Authorization

- Use only on networks and systems you own or have explicit written permission to test.
- This tool refuses to run unless you provide `--attest` with a statement of authorization for the scope.

## Command Line Options

```
Usage: sockprobe [OPTIONS] --targets <TARGETS>... --ports <PORTS> --attest <ATTEST>

Options:
      --targets <TARGETS>...       IP(s), CIDR(s), or range(s) like 192.168.1.10-192.168.1.250
      --ports <PORTS>              Port list/ranges, e.g., 1080 or 1080,1081,2000-2010
      --out <OUT>                  JSONL output file
      --concurrency <CONCURRENCY>  Concurrency level [default: 128]
      --connect-timeout <CONNECT_TIMEOUT>  Connect timeout in seconds [default: 2.0]
      --attest <ATTEST>            Statement: you are authorized to scan this scope
      --user <USER>                Username for user/pass auth (no brute force)
      --password <PASSWORD>        Password for user/pass auth
      --verify <VERIFY>            Verify via CONNECT to dest (IPv4:port) within allowed scope
      --allow-loopback             Allow 127.0.0.0/8
      --enable-public              Allow public IPs ONLY if explicitly allowlisted with --allowlist
      --allowlist <ALLOWLIST>...   Explicit IPv4 allowlist CIDRs (in addition to RFC1918). Required if --enable-public is set
      --max-targets <MAX_TARGETS>  Cap total sockets per run [default: 4096]
      --blocklist-file <BLOCKLIST_FILE>  Path to blocklist YAML file
  -h, --help                       Print help
  -V, --version                    Print version
```

## Input Formats

### Target Specifications

- **Single IP**: `192.168.1.10`
- **CIDR Block**: `192.168.1.0/24`
- **IP Range**: `192.168.1.10-192.168.1.50`

Multiple targets can be specified:
```bash
sockprobe --targets 192.168.1.0/24 10.0.0.0/16 --ports 1080 --attest "authorized"
```

### Port Specifications

- **Single Port**: `1080`
- **Multiple Ports**: `1080,1081,8080`
- **Port Ranges**: `1080-1090`
- **Mixed**: `1080,1081,8080-8090`

## Output Format

The tool outputs findings in JSONL format (one JSON object per line):

```json
{
  "ip": "192.168.1.10",
  "port": 1080,
  "connect_ok": true,
  "protocol": "socks5",
  "no_auth": true,
  "userpass_offered": null,
  "userpass_success": null,
  "verified": true,
  "banner_like": null,
  "latency_ms": 42,
  "error": null,
  "timestamp": "2023-05-15T10:30:45.123456789Z"
}
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `ip` | Target IP address |
| `port` | Target port |
| `connect_ok` | Whether TCP connection was successful |
| `protocol` | Detected protocol (`socks5`, `socks4_or_4a`, or null) |
| `no_auth` | Whether no-auth method is supported (SOCKS5) |
| `userpass_offered` | Whether username/password auth is offered (SOCKS5) |
| `userpass_success` | Whether username/password auth succeeded (SOCKS5) |
| `verified` | Whether verification CONNECT succeeded |
| `banner_like` | Banner-like information for non-standard responses |
| `latency_ms` | Connection latency in milliseconds |
| `error` | Error message if connection failed |
| `timestamp` | UTC timestamp of the scan |

## Blocklist File

You can create a blocklist file to specify additional networks that should never be scanned. The file should contain CIDR notation networks, one per line:

```yaml
# blocklist.yaml
# Add any networks you want to explicitly block from scanning

# Corporate networks to never scan
# 192.168.10.0/24
# 10.20.0.0/16

# Production networks
# 172.20.0.0/16
```

Lines starting with `#` are treated as comments and ignored.

## Security Features

### Authorization Attestation
All scans require an attestation statement to prevent accidental misuse:

```bash
sockprobe --targets 192.168.1.0/24 --ports 1080 \
  --attest "I have authorization to scan 192.168.1.0/24" --out results.jsonl
```

### Default Allowlist
By default, only RFC1918 private networks are scanned:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

### Special Network Blocking
These networks are always blocked:
- 0.0.0.0/8
- 127.0.0.0/8 (loopback, unless `--allow-loopback` is specified)
- 169.254.0.0/16 (link-local)
- 100.64.0.0/10 (CGNAT)
- 192.0.0.0/24
- 192.0.2.0/24 (TEST-NET-1)
- 198.18.0.0/15 (benchmarking)
- 192.88.99.0/24 (6to4 relay)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24 (TEST-NET-3)
- 224.0.0.0/4 (multicast)
- 240.0.0.0/4 (future/reserved)
- 255.255.255.255/32

### Verification Safeguards
SOCKS4/4a detection is only performed if a verification target is provided and is within the allowlist to prevent relaying to arbitrary destinations.

## Building and Running

To build and run the scanner:

```bash
# Build the project
cargo build --release

# Run with example parameters
./target/release/sockprobe --targets 192.168.1.0/24 --ports 1080 \
  --attest "authorized to test 192.168.1.0/24" --out results.jsonl
```

## Processing Results

Results are output in JSONL format, making them easy to process with standard tools:

### Using jq to filter successful SOCKS5 connections:
```bash
cat results.jsonl | jq 'select(.protocol == "socks5" and .connect_ok == true)'
```

### Using jq to count proxies by type:
```bash
cat results.jsonl | jq -r '.protocol' | sort | uniq -c
```

### Using grep to find verified proxies:
```bash
grep '"verified":true' results.jsonl
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support the Project

If you find this project helpful, consider buying me a coffee!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/muhiminulhasan)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Rust community for the excellent ecosystem
- Inspired by the need for safe, authorized network scanning tools


## Disclaimer:
This tool is intended for EDUCATIONAL and AUTHORIZED testing purposes only.
You must have **explicit permission** from the network owner before scanning.
The author(s) assume NO responsibility for any misuse, damage, or legal consequences
resulting from the use of this software.