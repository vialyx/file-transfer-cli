# 🔐 Secure File Transfer CLI

A secure file transfer application built in Rust demonstrating TLS encryption, secure socket programming, and cryptographic integrity verification.

## Features

- **TLS 1.2/1.3 Encryption** - All data encrypted in transit using modern cipher suites
- **Certificate Management** - Generate self-signed certificates or use CA-signed certs
- **File Integrity** - SHA-256 hash verification for all transfers
- **Async I/O** - High-performance transfers using Tokio
- **Progress Bars** - Visual feedback for file operations
- **Path Security** - Protection against directory traversal attacks

## Installation

```bash
# Clone the repository
git clone https://github.com/maksimvialykh/file-transfer-cli.git
cd file-transfer-cli

# Build the project
cargo build --release

# The binary will be at ./target/release/sft
```

## Quick Start

### 1. Generate TLS Certificates

```bash
# Generate self-signed certificate for localhost
sft cert generate --output ./certs

# With custom options
sft cert generate --output ./certs --cn myserver.local --dns "myserver.local,localhost" --ip "127.0.0.1,192.168.1.100"
```

### 2. Start the Server

```bash
sft server --cert ./certs/cert.pem --key ./certs/key.pem --storage ./files
```

Options:
- `--bind` - Address to bind (default: `0.0.0.0:8443`)
- `--storage` - Directory for file storage (default: `./storage`)
- `--max-size` - Maximum file size in MB (default: `1024`)

### 3. Transfer Files

```bash
# Upload a file
sft upload --ca ./certs/cert.pem myfile.txt

# Upload with custom remote name
sft upload --ca ./certs/cert.pem myfile.txt --name backup/myfile.txt

# Download a file
sft download --ca ./certs/cert.pem remote_file.txt local_copy.txt

# List files on server
sft list --ca ./certs/cert.pem

# Delete a file
sft delete --ca ./certs/cert.pem old_file.txt

# Test connection
sft ping --ca ./certs/cert.pem
```

## Security Concepts

### TLS (Transport Layer Security)

TLS provides three key security properties:

| Property | Description |
|----------|-------------|
| **Confidentiality** | Data is encrypted; eavesdroppers see only ciphertext |
| **Integrity** | Any modification to data is detected |
| **Authentication** | Server identity is verified via certificates |

### TLS Handshake

```
Client                                    Server
  |                                          |
  |-------- ClientHello ------------------>  |
  |         (supported ciphers, TLS version) |
  |                                          |
  |<------- ServerHello -------------------  |
  |         (selected cipher)                |
  |<------- Certificate -------------------  |
  |         (server's X.509 certificate)     |
  |<------- ServerKeyExchange -------------  |
  |         (ECDHE parameters)               |
  |                                          |
  |-------- ClientKeyExchange ------------>  |
  |         (client's ECDHE public key)      |
  |-------- ChangeCipherSpec ------------->  |
  |-------- Finished --------------------->  |
  |                                          |
  |<------- ChangeCipherSpec --------------  |
  |<------- Finished ----------------------  |
  |                                          |
  |========= Encrypted Application Data ====|
```

### Cipher Suite

This implementation uses strong, modern cipher suites:

- **TLS 1.3**: `TLS_AES_256_GCM_SHA384`
- **Key Exchange**: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- **Authentication**: RSA or ECDSA certificates
- **Encryption**: AES-256-GCM (authenticated encryption)

### Perfect Forward Secrecy (PFS)

Using ECDHE key exchange ensures that:
- Each session uses unique encryption keys
- Compromising the server's private key doesn't decrypt past sessions
- Provides protection against future key compromise

### File Integrity

All file transfers include SHA-256 hash verification:

```
Upload:  Client calculates hash → Server verifies after receiving
Download: Server sends hash → Client verifies after receiving
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI (clap)                               │
│  ┌─────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐           │
│  │  cert   │ │ server  │ │ upload │ │ download │  ...      │
│  └─────────┘ └─────────┘ └────────┘ └──────────┘           │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│                   TLS Layer (rustls)                         │
│  • Certificate validation    • Modern cipher suites         │
│  • Server authentication     • TLS 1.2 / 1.3               │
│  • Perfect Forward Secrecy   • No legacy algorithms         │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│                   Protocol Layer                             │
│  • Length-prefixed messages  • Request/Response types       │
│  • SHA-256 hash verification • Path traversal prevention    │
└─────────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│                   Network Layer (tokio)                      │
│  • Async TCP streams         • Concurrent connections       │
│  • Buffered I/O              • Connection limits            │
└─────────────────────────────────────────────────────────────┘
```

## Protocol

### Message Format

```
+------------+------------+------------------+
| Magic (4B) | Length (4B)| JSON Payload     |
+------------+------------+------------------+
| "SFT1"     | Big-endian | Request/Response |
+------------+------------+------------------+
```

### Request Types

| Type | Description |
|------|-------------|
| `Upload` | Request to upload a file (includes size, hash) |
| `Download` | Request to download a file |
| `List` | List files in a directory |
| `Delete` | Delete a file |
| `Ping` | Connection keep-alive |

### Data Transfer

File data is sent in 64KB chunks with length prefixes:

```
+------------+------------------+
| Length (4B)| Chunk Data       |
+------------+------------------+
```

End of transfer is indicated by a zero-length chunk.

## Security Considerations

### Production Deployment

1. **Use CA-signed certificates** - Don't use self-signed certs in production
2. **Protect private keys** - Keys should have `600` permissions
3. **Use firewall rules** - Restrict access to the server port
4. **Enable logging** - Use `-v` flag for verbose logging
5. **Regular updates** - Keep dependencies updated for security patches

### Certificate Verification

```bash
# Production: Always verify server certificate
sft upload --ca /path/to/ca-cert.pem file.txt

# Development only: Skip verification (INSECURE!)
sft upload --insecure file.txt
```

⚠️ **Never use `--insecure` in production!** It disables all TLS security guarantees.

### Path Traversal Protection

The server validates all filenames to prevent:
- `../` directory traversal attacks
- Absolute path access
- Hidden file access (files starting with `.`)

## Development

```bash
# Run tests
cargo test

# Run with verbose logging
cargo run -- -v server --cert ./certs/cert.pem --key ./certs/key.pem

# Check for security issues
cargo audit
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `rustls` | TLS implementation (pure Rust, no OpenSSL) |
| `tokio` | Async runtime |
| `tokio-rustls` | Async TLS streams |
| `rcgen` | Certificate generation |
| `clap` | CLI argument parsing |
| `sha2` | SHA-256 hashing |
| `serde` | Serialization |

## License

MIT License - see [LICENSE](LICENSE)

## References

- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)
- [rustls Documentation](https://docs.rs/rustls)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
