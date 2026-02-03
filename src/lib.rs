//! Secure File Transfer CLI
//!
//! A secure file transfer application using TLS encryption.
//!
//! ## Features
//! - TLS 1.2/1.3 encrypted connections
//! - File upload and download with integrity verification
//! - Self-signed certificate generation
//! - Progress bars for transfers
//!
//! ## Usage
//!
//! ```bash
//! # Generate certificates
//! sft cert generate --output ./certs
//!
//! # Start server
//! sft server --cert ./certs/cert.pem --key ./certs/key.pem --storage ./files
//!
//! # Upload a file
//! sft upload --ca ./certs/cert.pem myfile.txt
//!
//! # Download a file
//! sft download --ca ./certs/cert.pem myfile.txt local_copy.txt
//! ```

pub mod client;
pub mod protocol;
pub mod server;
pub mod tls;

pub use client::{Client, ClientConfig, ClientSession};
pub use protocol::{Request, Response};
pub use server::{Server, ServerConfig};
pub use tls::{ClientTlsConfig, ServerTlsConfig};
