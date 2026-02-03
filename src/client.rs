//! Secure File Transfer Client Module
//!
//! This module implements a TLS-secured file transfer client that:
//! - Establishes encrypted connections to the server
//! - Uploads and downloads files securely
//! - Verifies file integrity using SHA-256 hashes
//! - Provides progress indication for transfers
//!
//! ## TLS Client Security
//!
//! The client performs several security checks:
//! 1. **Server Certificate Verification**: Validates the server's certificate
//!    against trusted CAs (or custom CA for self-signed certs)
//! 2. **Server Name Indication (SNI)**: Sends the expected server name
//!    during TLS handshake for virtual hosting support
//! 3. **Certificate Chain Validation**: Verifies the complete chain of trust
//!
//! ## Connection Security
//!
//! ```text
//! Client                                    Server
//!   |                                          |
//!   |-------- TCP SYN -------------------->   |
//!   |<------- TCP SYN+ACK ----------------    |
//!   |-------- TCP ACK -------------------->   |
//!   |                                          |
//!   |======== TLS Handshake ===============   |
//!   |  - ClientHello (cipher suites, SNI)     |
//!   |  - ServerHello (selected cipher)        |
//!   |  - Certificate (server's cert)          |
//!   |  - ServerKeyExchange (for ECDHE)        |
//!   |  - ClientKeyExchange                    |
//!   |  - ChangeCipherSpec                     |
//!   |  - Finished                             |
//!   |=========================================|
//!   |                                          |
//!   |  [All traffic now encrypted]            |
//! ```

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::protocol::{
    ErrorCode, FileInfo, MessageFramer, ProtocolError, Request, Response, StreamingHasher,
    CHUNK_SIZE,
};
use crate::tls::ClientTlsConfig;

/// Client configuration
pub struct ClientConfig {
    /// Server address to connect to
    pub server_addr: SocketAddr,
    /// TLS configuration
    pub tls_config: ClientTlsConfig,
}

/// Secure file transfer client
pub struct Client {
    config: ClientConfig,
}

impl Client {
    /// Create a new client instance
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Connect to the server and return a connected session
    pub async fn connect(&self) -> Result<ClientSession> {
        info!("🔗 Connecting to {}...", self.config.server_addr);

        // Create TCP connection
        let tcp_stream = TcpStream::connect(&self.config.server_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", self.config.server_addr))?;

        debug!("TCP connection established");

        // Create TLS connector
        let connector = TlsConnector::from(self.config.tls_config.config.clone());

        // Perform TLS handshake
        let tls_stream = connector
            .connect(self.config.tls_config.server_name.clone(), tcp_stream)
            .await
            .context("TLS handshake failed")?;

        info!("🔐 TLS connection established");

        // Get connection info
        let (_, conn_info) = tls_stream.get_ref();
        if let Some(protocol) = conn_info.protocol_version() {
            info!("  Protocol: {:?}", protocol);
        }
        if let Some(cipher) = conn_info.negotiated_cipher_suite() {
            info!("  Cipher: {:?}", cipher.suite());
        }

        Ok(ClientSession {
            stream: tls_stream,
        })
    }
}

/// Connected client session
pub struct ClientSession {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

impl ClientSession {
    /// Upload a file to the server
    pub async fn upload(&mut self, local_path: &Path, remote_name: &str) -> Result<()> {
        // Check if file exists
        if !local_path.exists() {
            anyhow::bail!("File not found: {:?}", local_path);
        }

        // Get file metadata
        let metadata = fs::metadata(local_path)
            .await
            .with_context(|| format!("Failed to read metadata for {:?}", local_path))?;

        if metadata.is_dir() {
            anyhow::bail!("Cannot upload a directory: {:?}", local_path);
        }

        let file_size = metadata.len();

        // Calculate file hash
        info!("📊 Calculating file hash...");
        let hash = Self::calculate_file_hash(local_path).await?;
        info!("  Hash: {}", hash);

        // Split stream
        let (reader, writer) = tokio::io::split(&mut self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send upload request
        let request = Request::Upload {
            filename: remote_name.to_string(),
            size: file_size,
            sha256_hash: hash,
        };

        MessageFramer::write_message(&mut writer, &request)
            .await
            .context("Failed to send upload request")?;

        // Wait for acceptance
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read response")?;

        match response {
            Response::UploadAccepted => {
                info!("📤 Upload accepted, sending file...");
            }
            Response::Error { code, message } => {
                anyhow::bail!("Upload rejected: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }

        // Open file and send data
        let file = File::open(local_path).await?;
        let mut file_reader = BufReader::new(file);
        let mut buffer = vec![0u8; CHUNK_SIZE];

        let pb = create_progress_bar(file_size);
        pb.set_message("Uploading");

        let mut bytes_sent: u64 = 0;

        loop {
            let bytes_read = file_reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            MessageFramer::write_data(&mut writer, &buffer[..bytes_read])
                .await
                .context("Failed to send file data")?;

            bytes_sent += bytes_read as u64;
            pb.set_position(bytes_sent);
        }

        // Send end marker
        MessageFramer::write_end_marker(&mut writer).await?;

        pb.finish_with_message("Upload complete");

        // Wait for completion response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read completion response")?;

        match response {
            Response::UploadComplete { bytes_received } => {
                info!(
                    "✅ Upload complete: {} bytes transferred",
                    bytes_received
                );
                Ok(())
            }
            Response::Error { code, message } => {
                anyhow::bail!("Upload failed: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }
    }

    /// Download a file from the server
    pub async fn download(&mut self, remote_name: &str, local_path: &Path) -> Result<()> {
        // Check if local path already exists
        if local_path.exists() {
            warn!("⚠️  Local file already exists: {:?}", local_path);
            // Could prompt for overwrite, for now just warn
        }

        // Ensure parent directory exists
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Split stream
        let (reader, writer) = tokio::io::split(&mut self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send download request
        let request = Request::Download {
            filename: remote_name.to_string(),
        };

        MessageFramer::write_message(&mut writer, &request)
            .await
            .context("Failed to send download request")?;

        // Wait for ready response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read response")?;

        let (file_size, expected_hash) = match response {
            Response::DownloadReady { size, sha256_hash } => {
                info!(
                    "📥 Download ready: {} bytes, hash: {}",
                    size, sha256_hash
                );
                (size, sha256_hash)
            }
            Response::Error { code, message } => {
                anyhow::bail!("Download rejected: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        };

        // Create local file
        let file = File::create(local_path)
            .await
            .with_context(|| format!("Failed to create file: {:?}", local_path))?;
        let mut file_writer = BufWriter::new(file);

        let pb = create_progress_bar(file_size);
        pb.set_message("Downloading");

        let mut hasher = StreamingHasher::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];

        // Receive file data
        loop {
            let chunk_size = MessageFramer::read_data(&mut reader, &mut buffer)
                .await
                .context("Failed to read file data")?;

            if chunk_size == 0 {
                break;
            }

            hasher.update(&buffer[..chunk_size]);
            file_writer.write_all(&buffer[..chunk_size]).await?;
            pb.set_position(hasher.bytes_processed());
        }

        // Flush file
        file_writer.flush().await?;

        pb.finish_with_message("Download complete");

        // Get bytes processed before consuming hasher
        let bytes_downloaded = hasher.bytes_processed();

        // Verify hash
        let actual_hash = hasher.finalize();
        if actual_hash != expected_hash {
            // Delete corrupted file
            fs::remove_file(local_path).await?;
            anyhow::bail!(
                "Hash mismatch! Expected: {}, Got: {}. File deleted.",
                expected_hash,
                actual_hash
            );
        }

        // Read completion response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read completion response")?;

        match response {
            Response::DownloadComplete => {
                info!(
                    "✅ Download complete: {} bytes, hash verified",
                    bytes_downloaded
                );
                Ok(())
            }
            Response::Error { code, message } => {
                anyhow::bail!("Download failed: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }
    }

    /// List files on the server
    pub async fn list(&mut self, path: Option<&str>) -> Result<Vec<FileInfo>> {
        // Split stream
        let (reader, writer) = tokio::io::split(&mut self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send list request
        let request = Request::List {
            path: path.map(String::from),
        };

        MessageFramer::write_message(&mut writer, &request)
            .await
            .context("Failed to send list request")?;

        // Read response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read response")?;

        match response {
            Response::FileList { files } => Ok(files),
            Response::Error { code, message } => {
                anyhow::bail!("List failed: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }
    }

    /// Delete a file on the server
    pub async fn delete(&mut self, filename: &str) -> Result<()> {
        // Split stream
        let (reader, writer) = tokio::io::split(&mut self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send delete request
        let request = Request::Delete {
            filename: filename.to_string(),
        };

        MessageFramer::write_message(&mut writer, &request)
            .await
            .context("Failed to send delete request")?;

        // Read response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read response")?;

        match response {
            Response::Deleted { filename } => {
                info!("🗑️  Deleted: {}", filename);
                Ok(())
            }
            Response::Error { code, message } => {
                anyhow::bail!("Delete failed: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }
    }

    /// Ping the server
    pub async fn ping(&mut self) -> Result<()> {
        // Split stream
        let (reader, writer) = tokio::io::split(&mut self.stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Send ping
        MessageFramer::write_message(&mut writer, &Request::Ping)
            .await
            .context("Failed to send ping")?;

        // Read response
        let response: Response = MessageFramer::read_message(&mut reader)
            .await
            .context("Failed to read response")?;

        match response {
            Response::Pong => {
                info!("🏓 Pong received");
                Ok(())
            }
            Response::Error { code, message } => {
                anyhow::bail!("Ping failed: {:?} - {}", code, message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }
    }

    /// Calculate SHA-256 hash of a file
    async fn calculate_file_hash(path: &Path) -> Result<String> {
        let file = File::open(path).await?;
        let mut reader = BufReader::new(file);
        let mut hasher = StreamingHasher::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }
}

/// Create progress bar for transfers
fn create_progress_bar(total_size: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// Format file size for display
pub fn format_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

/// Format timestamp for display
pub fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    
    // Simple formatting without external crate
    let duration = datetime
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    // Calculate date components (simplified)
    let secs = duration.as_secs();
    let days = secs / 86400;
    let years = 1970 + days / 365; // Approximate
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    
    format!("{}-{:02}-{:02}", years, months, day)
}
