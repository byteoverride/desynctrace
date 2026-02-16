# DesyncTrace

DesyncTrace is a professional-grade detection and exploitation tool for HTTP Request Smuggling (HTTP Desynchronization) vulnerabilities. It supports diverse attack vectors including classic HTTP/1.1 desyncs (CL.TE, TE.CL) and modern HTTP/2 downgrade attacks (H2.CL, H2.TE, H2.CRLF).

## 🚀 Features

- **Wide Vector Support**:
    - **CL.TE**: Content-Length precedence vs Transfer-Encoding.
    - **TE.CL**: Transfer-Encoding precedence vs Content-Length.
    - **TE.TE**: Obfuscated Transfer-Encoding headers.
    - **CL.0**: Backend ignores Content-Length/Body.
    - **H2.CL**: HTTP/2 -> HTTP/1.1 downgrade with `Content-Length: 0` and a body.
    - **H2.TE**: HTTP/2 -> HTTP/1.1 downgrade with injected `Transfer-Encoding`.
    - **H2.CRLF**: HTTP/2 Header Splitting via CRLF injection.
- **Smart Detection**:
    - **Blind Detection**: Uses timing-based analysis to detect desynchronization without relying on reflected responses.
    - **Poisoning Verification**: Confirms vulnerabilities by poisoning the backend socket and checking if subsequent requests are affected.
- **Advanced Capabilities**:
    - **Raw HTTP/2 Client**: Bypasses standard library protections to send malformed H2 frames.
    - **Smuggling-Specific Headers**: Handles manual formatting of headers to test specific parser behaviors.
- **User Friendly**:
    - **Progress Bars**: Visual feedback during long scans.
    - **Formatted Reports**: Clear tables and JSON output.
    - **Man Pages**: Built-in documentation generator.

## 📦 Installation

```bash
go install github.com/byteoverride/desynctrace@latest
```

### From Source
```bash
git clone https://github.com/byteoverride/desynctrace.git
cd desynctrace
go build -o desynctrace ./cmd/desynctrace
```
(Requires Go 1.21+)

### Using Docker
```bash
docker build -t desynctrace .
docker run -it desynctrace --help
```

## 📖 User Guide

### 1. Scanning (`scan`)
The main function of DesyncTrace. It tests a target URL against all registered smuggling vectors.

**Basic Usage:**
```bash
./desynctrace scan https://example.com
```

**Authenticated Scan:**
If the target requires login, use the `--cookie` flag.
```bash
./desynctrace scan https://admin.example.com --cookie "session=k3jh4k234..."
```

**Using a Proxy (e.g., Burp Suite):**
To route traffic through Burp Suite (useful for debugging or capturing requests):
```bash
./desynctrace scan https://example.com --proxy http://127.0.0.1:8080
```

**Performance Tuning:**
Adjust the number of concurrent threads (default 10):
```bash
./desynctrace scan https://example.com --threads 50
```

### 2. Exploitation (`exploit`)
Generates Proof-of-Concept (PoC) payloads for confirmed vulnerabilities.

**Generate a PoC:**
You must specify the vector you want to exploit.
```bash
./desynctrace exploit https://example.com --vector CL.TE --poc
```

**Supported Vectors for Exploit:**
- `CL.TE`
- `TE.CL`
- `H2.CL`

### 3. Reporting (`report`)
*Currently a placeholder for future functionality. Scans automatically save a `desynctrace_report.json` file.*

```bash
./desynctrace report --format html --output ./results
```

### 4. Documentation (`docs`)
Generates standard Man pages and Markdown documentation for the tool itself.

```bash
./desynctrace docs --dir ./docs
```

## 🛠️ Configuration
You can persistently configure the tool using a `.desynctrace.yaml` file in your home directory.

**Example `.desynctrace.yaml`:**
```yaml
target: "https://example.com"
proxy: "http://127.0.0.1:8080"
threads: 20
verbose: true
cookie: "session=xyz"
```

## 🧩 Vector Explanations

| Vector | Description |
| :--- | :--- |
| **CL.TE** | Front-end uses `Content-Length`, Back-end uses `Transfer-Encoding`. Payload is smuggled after the chunk end. |
| **TE.CL** | Front-end uses `Transfer-Encoding`, Back-end uses `Content-Length`. Payload is smuggled inside the chunked body. |
| **TE.TE** | Both support TE, but one is tricked into ignoring it via obfuscation (e.g., `Transfer-Encoding: chunked\v`). |
| **CL.0** | Front-end forwards body with CL, Back-end ignores body (CL=0). Body becomes the next request. |
| **H2.CL** | HTTP/2 request with `Content-Length: 0` and a body. Downgrades to H1.1 where backend sees body as next request. |
| **H2.TE** | HTTP/2 request with injected `Transfer-Encoding` header. Downgrades to H1.1 causing TE conflict. |
| **H2.CRLF** | Injecting newlines (`\r\n`) in H2 headers to split them into multiple H1 headers during downgrade. |

## ⚠️ Disclaimer
This tool is for **educational and authorized testing purposes only**. Using this tool against systems you do not have explicit permission to test is illegal and unethical. The authors are not responsible for any misuse.

## License
MIT
