# DesyncTrace

A professional-grade HTTP request smuggling detection and exploitation tool written in Go. DesyncTrace tests for 14 vector classes using differential timing analysis and connection poisoning confirmation, with over 100 individual payload variants. It can both detect vulnerabilities and execute live attacks with full traffic visibility.

## Features

### Detection Engine
- **Differential Timing Analysis** -- Safe, non-intrusive detection using James Kettle's paired-request technique. Sends probes that should timeout only if the backend disagrees on message boundaries. Statistical confirmation across multiple attempts.
- **Connection Poisoning Confirmation** -- Proves exploitability by smuggling requests to canary paths on the same TCP socket. If the victim response matches the smuggled path, the vulnerability is confirmed.
- **Server Fingerprinting** -- Identifies CDNs (Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door), WAFs (Imperva, F5, ModSecurity), reverse proxies (HAProxy, Varnish, Envoy, Traefik, AWS ALB), and backend servers. Automatically prioritizes vectors based on known-vulnerable stack combinations.

### Live Exploitation
- **Execute attacks directly** -- Send smuggling payloads live against targets with `--execute` and see the desync happen in real time.
- **Raw traffic visibility** -- The `--show-traffic` flag prints every request and response byte during scanning, so you can see exactly what is being sent and received.
- **PoC generation** -- Also generates ready-to-use payloads in raw, curl, Python, ncat, and Turbo Intruder formats for offline use.

### Attack Vectors (14 Classes, 100+ Payloads)

| Vector | Description |
| :--- | :--- |
| **CL.TE** | Frontend uses Content-Length, backend uses Transfer-Encoding. 10 payload variants including prefix corruption, full request smuggling, request hijacking, trailer injection, and response queue poisoning. |
| **TE.CL** | Frontend uses Transfer-Encoding, backend uses Content-Length. 8 variants including timing probes, request capture, method change, header ordering, and cache poisoning. |
| **TE.TE** | Obfuscated Transfer-Encoding headers. 30+ obfuscation techniques including null bytes, zero-width spaces, BOM prefix, line folding, mixed case, underscores, quoted values, and duplicate headers. |
| **CL.0** | Backend ignores the body entirely. 10 variants across POST/GET/OPTIONS/HEAD methods, content-type mismatches, and path-specific targeting. |
| **H2.CL** | HTTP/2 to HTTP/1.1 downgrade with Content-Length mismatch. Raw H2 frame manipulation. |
| **H2.TE** | HTTP/2 with injected Transfer-Encoding header (forbidden by spec but forwarded by some proxies). |
| **H2.CRLF** | CRLF injection in HTTP/2 header values to split headers during H1 downgrade. 6 injection points. |
| **Double-CL** | Duplicate Content-Length headers with different values. Tests first-wins vs last-wins behavior. |
| **Chunk-Ext** | Chunk extension parsing disagreements. Leading zeros, 0x prefix, bare LF, CRLF in extensions, quoted values. |
| **CL.Spacing** | Content-Length value formatting tricks. Signs, hex, octal, leading zeros, trailing characters, obs-fold. |
| **H2.Pseudo** | HTTP/2 pseudo-header manipulation. Duplicate :method, full URL in :path, :scheme override, double encoding. |
| **H2.Tunnel** | HTTP/2 CONNECT tunneling and h2c upgrade smuggling for proxy bypass and SSRF. |
| **WS.Smuggle** | WebSocket upgrade smuggling. Tricks proxies into tunnel mode to bypass HTTP inspection. |
| **HTTP/0.9** | HTTP version confusion. HTTP/0.9 requests, HTTP/1.0 keep-alive desync, invalid version strings, request line malformation. |

### Exploit Scenarios
- `acl-bypass` -- Smuggle requests to restricted paths that the frontend blocks
- `request-hijack` -- Capture the next user's request including cookies and auth headers
- `cache-poison` -- Poison CDN/proxy cache with attacker-controlled content
- `response-queue` -- Desync response queue via HEAD smuggling
- `xss-poison` -- XSS through response queue poisoning
- `cred-capture` -- Redirect next user's request to capture credentials

### Clients
- **PipelinedClient** -- Raw TCP/TLS with connection reuse. Sends attack and victim requests on the same socket for poisoning confirmation and live exploitation.
- **RawH2Client** -- Raw HTTP/2 frame writer. Bypasses HPACK/framing restrictions to send malformed H2 requests. Proper SETTINGS/PING/WINDOW_UPDATE handling.
- **FastHTTPClient** -- High-performance client for fingerprinting and baseline requests.

## Installation

```bash
go install github.com/byteoverride/desynctrace/cmd/desynctrace@latest
```

Requires Go 1.24 or later.

### From Source

```bash
git clone https://github.com/byteoverride/desynctrace.git
cd desynctrace
go build -o desynctrace ./cmd/desynctrace
```

### Docker

```bash
docker build -t desynctrace .
docker run -it desynctrace --help
```

## Usage

### Scanning

Basic scan against a target:

```bash
desynctrace scan https://example.com
```

Safe mode (timing detection only, no connection poisoning):

```bash
desynctrace scan https://example.com --safe
```

Show raw request/response traffic during scanning:

```bash
desynctrace scan https://example.com --show-traffic
```

Authenticated scan with cookies:

```bash
desynctrace scan https://example.com --cookie "session=abc123"
```

Route through Burp Suite:

```bash
desynctrace scan https://example.com --proxy http://127.0.0.1:8080
```

Test specific vectors only:

```bash
desynctrace scan https://example.com --vectors CL.TE,TE.CL,TE.TE
```

Scan multiple targets from a file:

```bash
desynctrace scan --targets targets.txt
```

Test multiple paths per target:

```bash
desynctrace scan https://example.com --paths paths.txt
```

Control concurrency and timing:

```bash
desynctrace scan https://example.com --threads 10 --delay 200 --attempts 8
```

Skip HTTP/2 vectors:

```bash
desynctrace scan https://example.com --skip-h2
```

Output formats:

```bash
desynctrace scan https://example.com -f json -o report.json
desynctrace scan https://example.com -f markdown -o report.md
desynctrace scan https://example.com -f text -o report.txt
```

### Live Exploitation

Execute a live attack against a target and see the traffic:

```bash
desynctrace exploit https://example.com --vector CL.TE --execute
```

Control attempt count and delay between attack/victim requests:

```bash
desynctrace exploit https://example.com --vector CL.TE --execute \
  --exec-attempts 5 --exec-delay 200
```

Choose an exploitation scenario:

```bash
desynctrace exploit https://example.com --vector CL.TE --execute --scenario request-hijack
desynctrace exploit https://example.com --vector TE.CL --execute --scenario cache-poison
desynctrace exploit https://example.com --vector CL.TE --execute --scenario response-queue
```

Customize the smuggled request:

```bash
desynctrace exploit https://example.com --vector CL.TE --execute \
  --smuggle-path /api/admin/users \
  --smuggle-method POST \
  --smuggle-host internal.example.com
```

### PoC Generation

Generate a PoC payload without sending it:

```bash
desynctrace exploit https://example.com --vector CL.TE
```

Generate PoCs for all scenarios at once:

```bash
desynctrace exploit https://example.com --vector CL.TE --all
```

Save the Python exploit script to a file:

```bash
desynctrace exploit https://example.com --vector CL.TE \
  --scenario acl-bypass --output-script exploit.py
```

### Documentation

Generate man pages and markdown docs:

```bash
desynctrace docs --dir ./docs
```

## Scan Output Example

```
 DESYNCTRACE SCAN REPORT - https://example.com
 Duration: 45.2s
 Fingerprint: Server: nginx/1.24.0 | Proxy: haproxy | H2: yes | TLS: TLS 1.3

+-----------+------------+------------------------+-----------+---------------------------+
| VECTOR    | CONFIDENCE | TECHNIQUE              | STATUS    | EVIDENCE                  |
+-----------+------------+------------------------+-----------+---------------------------+
| CL.TE     | 95%        | differential-timing    | SUSPECTED | 5/5 probes timed out ...  |
| CL.TE     | 90%        | connection-poisoning   | CONFIRMED | 3/3 attempts smuggled ... |
| TE.TE     | 85%        | differential-timing... | SUSPECTED | TE.TE via 'mixed-case'... |
+-----------+------------+------------------------+-----------+---------------------------+

 2 CONFIRMED vulnerabilities found!
 1 suspected (timing-based) findings - run without --safe to confirm.
```

## Traffic Output Example

When using `--show-traffic` or `--execute`, you see the raw bytes:

```
--- [probe 1/5] ---
  Elapsed: 5.012s
  >> REQUEST (142 bytes):
  > POST / HTTP/1.1
  > Host: example.com
  > Content-Type: application/x-www-form-urlencoded
  > Transfer-Encoding: chunked
  > Content-Length: 6
  >
  > 1
  > Z
  << RESPONSE: 408 Request Timeout
```

## Configuration

Create `~/.desynctrace.yaml` for persistent settings:

```yaml
proxy: "http://127.0.0.1:8080"
threads: 10
verbose: true
```

Environment variables with `DESYNC_` prefix also work:

```bash
export DESYNC_PROXY=http://127.0.0.1:8080
export DESYNC_VERBOSE=true
```

## How It Works

DesyncTrace follows a three-phase detection pipeline:

**Phase 1: Fingerprinting** -- Identifies the server stack (CDN, proxy, WAF, backend) and prioritizes vectors that are known to affect that combination. For example, nginx + Gunicorn targets get CL.0 and CL.TE tested first. Servers without HTTP/2 support skip all H2 vectors.

**Phase 2: Differential Timing** -- For each vector, sends a probe request designed to trigger a timeout only if the backend parser disagrees with the frontend. CL.TE probes send an incomplete chunked body: if the backend uses Transfer-Encoding, it waits for more chunks and times out. Each probe runs multiple times (configurable via `--attempts`) and requires a majority to timeout before flagging.

**Phase 3: Connection Poisoning** -- For vectors flagged by timing, sends an attack request followed by a victim request on the same TCP connection using the PipelinedClient. The attack smuggles a GET to a random canary path. If the victim's response is a 404 or contains the canary, the vulnerability is confirmed as exploitable.

## All Flags

### scan

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--proxy` | `-p` | | Proxy URL (e.g., http://127.0.0.1:8080) |
| `--cookie` | | | Session cookie (e.g., session=xyz) |
| `--threads` | `-t` | 5 | Concurrent threads per target |
| `--safe` | | false | Timing detection only, no connection poisoning |
| `--output` | `-o` | | Output file path |
| `--format` | `-f` | json | Output format: json, markdown, text |
| `--targets` | | | File with target URLs (one per line) |
| `--paths` | | | File with paths to test (one per line) |
| `--delay` | | 0 | Delay between requests in milliseconds |
| `--attempts` | | 5 | Number of attempts per detection probe |
| `--skip-h2` | | false | Skip HTTP/2 vectors |
| `--vectors` | | | Comma-separated vector types to test |
| `--show-traffic` | | false | Print raw request/response bytes for each probe |

### exploit

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--vector` | | | Vector type to exploit (required) |
| `--execute` | `-x` | false | Send the attack live against the target |
| `--exec-attempts` | | 3 | Number of live attempts |
| `--exec-delay` | | 100 | Delay in ms between attack and victim requests |
| `--scenario` | | acl-bypass | Exploitation scenario |
| `--smuggle-path` | | /admin | Path for the smuggled request |
| `--smuggle-method` | | GET | HTTP method for the smuggled request |
| `--smuggle-host` | | | Override Host header in smuggled request |
| `--all` | | false | Generate PoCs for all scenarios |
| `--output-script` | | | Save Python exploit script to file |
| `--poc` | | false | Show full PoC payloads |

## Disclaimer

This tool is for authorized security testing and educational purposes only. Do not use it against systems you do not have explicit permission to test. The authors are not responsible for any misuse.

## License

MIT
