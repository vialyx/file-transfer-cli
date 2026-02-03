//! Secure File Transfer Server Module
//!
//! This module implements a TLS-secured file transfer server that:
//! - Accepts encrypted connections using TLS 1.2/1.3
//! - Handles concurrent client connections using Tokio
//! - Provides file upload, download, and listing operations
//! - Verifies file integrity using SHA-256 hashes
//!
//! ## Security Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    TLS Server                            │
//! │  ┌─────────────────────────────────────────────────────┐│
//! │  │              TLS Acceptor (rustls)                  ││
//! │  │  - Certificate-based authentication                 ││
//! │  │  - Perfect Forward Secrecy (ECDHE)                  ││
//! │  │  - Modern cipher suites only                        ││
//! │  └─────────────────────────────────────────────────────┘│
//! │                         │                                │
//! │  ┌─────────────────────────────────────────────────────┐│
//! │  │            Connection Handler                       ││
//! │  │  - Path validation (prevent traversal)              ││
//! │  │  - Size limits                                      ││
//! │  │  - Hash verification                                ││
//! │  └─────────────────────────────────────────────────────┘│
//! │                         │                                │
//! │  ┌─────────────────────────────────────────────────────┐│
//! │  │              File System                            ││
//! │  │  - Sandboxed storage directory                      ││
//! │  │  - Restricted permissions                           ││
//! │  └─────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────┘
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::protocol::{
    validate_filename, ErrorCode, FileInfo, MessageFramer, ProtocolError, Request, Response,
    StreamingHasher, CHUNK_SIZE,
};
use crate::tls::ServerTlsConfig;

/// Maximum concurrent connections
const MAX_CONNECTIONS: usize = 100;

/// Maximum file size (1 GB)
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Server configuration
pub struct ServerConfig {
    /// Address to bind to
    pub bind_addr: SocketAddr,
    /// Directory to store files
    pub storage_dir: PathBuf,
    /// TLS configuration
    pub tls_config: ServerTlsConfig,
    /// Maximum file size in bytes
    pub max_file_size: u64,
}

/// Secure file transfer server
pub struct Server {
    config: ServerConfig,
    connection_semaphore: Arc<Semaphore>,
}

impl Server {
    /// Create a new server instance
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    /// Start the server and listen for connections
    pub async fn run(&self) -> Result<()> {
        // Ensure storage directory exists with proper permissions
        self.setup_storage_directory().await?;

        // Create TCP listener
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.bind_addr))?;

        info!("🔒 Secure file transfer server listening on {}", self.config.bind_addr);
        info!("📁 Storage directory: {:?}", self.config.storage_dir);

        // Create TLS acceptor
        let tls_acceptor = TlsAcceptor::from(self.config.tls_config.config.clone());

        loop {
            // Accept new TCP connection
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            // Acquire connection permit
            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("Connection limit reached, rejecting {}", peer_addr);
                    continue;
                }
            };

            // Clone what we need for the spawned task
            let tls_acceptor = tls_acceptor.clone();
            let storage_dir = self.config.storage_dir.clone();
            let max_file_size = self.config.max_file_size;

            // Spawn handler task
            tokio::spawn(async move {
                let _permit = permit; // Keep permit alive

                match Self::handle_connection(tcp_stream, tls_acceptor, peer_addr, storage_dir, max_file_size)
                    .await
                {
                    Ok(()) => debug!("Connection from {} closed normally", peer_addr),
                    Err(e) => warn!("Connection from {} error: {}", peer_addr, e),
                }
            });
        }
    }

    /// Set up storage directory with proper permissions
    async fn setup_storage_directory(&self) -> Result<()> {
        if !self.config.storage_dir.exists() {
            fs::create_dir_all(&self.config.storage_dir)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create storage directory: {:?}",
                        self.config.storage_dir
                    )
                })?;
            info!("Created storage directory: {:?}", self.config.storage_dir);
        }

        // Set directory permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.config.storage_dir).await?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700); // Owner only
            fs::set_permissions(&self.config.storage_dir, permissions).await?;
        }

        Ok(())
    }

    /// Handle a single client connection
    async fn handle_connection(
        tcp_stream: TcpStream,
        tls_acceptor: TlsAcceptor,
        peer_addr: SocketAddr,
        storage_dir: PathBuf,
        max_file_size: u64,
    ) -> Result<()> {
        info!("📥 New connection from {}", peer_addr);

        // Perform TLS handshake
        let tls_stream = tls_acceptor
            .accept(tcp_stream)
            .await
            .context("TLS handshake failed")?;

        info!("🔐 TLS handshake successful with {}", peer_addr);

        // Split into read/write halves
        let (reader, writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        // Handle requests
        loop {
            // Read request
            let request: Request = match MessageFramer::read_message(&mut reader).await {
                Ok(req) => req,
                Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Client {} disconnected", peer_addr);
                    break;
                }
                Err(e) => {
                    error!("Failed to read request from {}: {}", peer_addr, e);
                    break;
                }
            };

            debug!("Request from {}: {:?}", peer_addr, request);

            // Process request
            let response = Self::process_request(
                request,
                &mut reader,
                &mut writer,
                &storage_dir,
                max_file_size,
            )
            .await;

            // Send response
            if let Err(e) = MessageFramer::write_message(&mut writer, &response).await {
                error!("Failed to send response to {}: {}", peer_addr, e);
                break;
            }
        }

        Ok(())
    }

    /// Process a client request
    async fn process_request<R, W>(
        request: Request,
        reader: &mut R,
        writer: &mut W,
        storage_dir: &Path,
        max_file_size: u64,
    ) -> Response
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        match request {
            Request::Upload {
                filename,
                size,
                sha256_hash,
            } => {
                Self::handle_upload(reader, writer, storage_dir, &filename, size, &sha256_hash, max_file_size)
                    .await
            }
            Request::Download { filename } => {
                Self::handle_download(writer, storage_dir, &filename).await
            }
            Request::List { path } => Self::handle_list(storage_dir, path.as_deref()).await,
            Request::Delete { filename } => Self::handle_delete(storage_dir, &filename).await,
            Request::Ping => Response::Pong,
        }
    }

    /// Handle file upload
    async fn handle_upload<R, W>(
        reader: &mut R,
        writer: &mut W,
        storage_dir: &Path,
        filename: &str,
        size: u64,
        expected_hash: &str,
        max_file_size: u64,
    ) -> Response
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        // Validate filename
        let safe_filename = match validate_filename(filename) {
            Ok(f) => f,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::InvalidPath,
                    message: e.to_string(),
                }
            }
        };

        // Check file size
        if size > max_file_size {
            return Response::Error {
                code: ErrorCode::StorageFull,
                message: format!("File too large: {} bytes (max: {})", size, max_file_size),
            };
        }

        // Create full path
        let file_path = storage_dir.join(&safe_filename);

        // Ensure parent directories exist
        if let Some(parent) = file_path.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to create directory: {}", e),
                };
            }
        }

        // Send acceptance response
        if let Err(e) = MessageFramer::write_message(writer, &Response::UploadAccepted).await {
            return Response::Error {
                code: ErrorCode::ServerError,
                message: format!("Failed to send acceptance: {}", e),
            };
        }

        info!("📤 Receiving file: {} ({} bytes)", safe_filename, size);

        // Create file
        let file = match File::create(&file_path).await {
            Ok(f) => f,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to create file: {}", e),
                }
            }
        };

        let mut file_writer = BufWriter::new(file);
        let mut hasher = StreamingHasher::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut total_received: u64 = 0;

        // Receive file data
        loop {
            let chunk_size = match MessageFramer::read_data(reader, &mut buffer).await {
                Ok(0) => break, // End of data
                Ok(n) => n,
                Err(e) => {
                    // Clean up partial file
                    let _ = fs::remove_file(&file_path).await;
                    return Response::Error {
                        code: ErrorCode::TransferAborted,
                        message: format!("Failed to receive data: {}", e),
                    };
                }
            };

            // Update hash
            hasher.update(&buffer[..chunk_size]);

            // Write to file
            if let Err(e) = file_writer.write_all(&buffer[..chunk_size]).await {
                let _ = fs::remove_file(&file_path).await;
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to write file: {}", e),
                };
            }

            total_received += chunk_size as u64;
        }

        // Flush file
        if let Err(e) = file_writer.flush().await {
            let _ = fs::remove_file(&file_path).await;
            return Response::Error {
                code: ErrorCode::ServerError,
                message: format!("Failed to flush file: {}", e),
            };
        }

        // Verify hash
        let actual_hash = hasher.finalize();
        if actual_hash != expected_hash {
            let _ = fs::remove_file(&file_path).await;
            return Response::Error {
                code: ErrorCode::HashMismatch,
                message: format!(
                    "Hash mismatch: expected {}, got {}",
                    expected_hash, actual_hash
                ),
            };
        }

        info!(
            "✅ File received: {} ({} bytes, hash: {})",
            safe_filename, total_received, actual_hash
        );

        Response::UploadComplete {
            bytes_received: total_received,
        }
    }

    /// Handle file download
    async fn handle_download<W>(
        writer: &mut W,
        storage_dir: &Path,
        filename: &str,
    ) -> Response
    where
        W: AsyncWriteExt + Unpin,
    {
        // Validate filename
        let safe_filename = match validate_filename(filename) {
            Ok(f) => f,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::InvalidPath,
                    message: e.to_string(),
                }
            }
        };

        let file_path = storage_dir.join(&safe_filename);

        // Check if file exists
        if !file_path.exists() {
            return Response::Error {
                code: ErrorCode::FileNotFound,
                message: format!("File not found: {}", safe_filename),
            };
        }

        // Get file metadata
        let metadata = match fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to read file metadata: {}", e),
                }
            }
        };

        if metadata.is_dir() {
            return Response::Error {
                code: ErrorCode::InvalidPath,
                message: "Cannot download a directory".to_string(),
            };
        }

        let file_size = metadata.len();

        // Calculate file hash
        let hash = match Self::calculate_file_hash(&file_path).await {
            Ok(h) => h,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to calculate hash: {}", e),
                }
            }
        };

        // Send ready response
        if let Err(e) = MessageFramer::write_message(
            writer,
            &Response::DownloadReady {
                size: file_size,
                sha256_hash: hash.clone(),
            },
        )
        .await
        {
            return Response::Error {
                code: ErrorCode::ServerError,
                message: format!("Failed to send ready response: {}", e),
            };
        }

        info!("📥 Sending file: {} ({} bytes)", safe_filename, file_size);

        // Open and send file
        let file = match File::open(&file_path).await {
            Ok(f) => f,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to open file: {}", e),
                }
            }
        };

        let mut file_reader = BufReader::new(file);
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let bytes_read = match file_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    return Response::Error {
                        code: ErrorCode::ServerError,
                        message: format!("Failed to read file: {}", e),
                    }
                }
            };

            if let Err(e) = MessageFramer::write_data(writer, &buffer[..bytes_read]).await {
                return Response::Error {
                    code: ErrorCode::TransferAborted,
                    message: format!("Failed to send data: {}", e),
                };
            }
        }

        // Send end marker
        if let Err(e) = MessageFramer::write_end_marker(writer).await {
            return Response::Error {
                code: ErrorCode::TransferAborted,
                message: format!("Failed to send end marker: {}", e),
            };
        }

        info!("✅ File sent: {} ({} bytes)", safe_filename, file_size);

        Response::DownloadComplete
    }

    /// Handle file listing
    async fn handle_list(storage_dir: &Path, subpath: Option<&str>) -> Response {
        let list_dir = if let Some(subpath) = subpath {
            match validate_filename(subpath) {
                Ok(safe_path) => storage_dir.join(safe_path),
                Err(e) => {
                    return Response::Error {
                        code: ErrorCode::InvalidPath,
                        message: e.to_string(),
                    }
                }
            }
        } else {
            storage_dir.to_path_buf()
        };

        if !list_dir.exists() {
            return Response::Error {
                code: ErrorCode::FileNotFound,
                message: "Directory not found".to_string(),
            };
        }

        let mut files = Vec::new();
        let mut entries = match fs::read_dir(&list_dir).await {
            Ok(e) => e,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::ServerError,
                    message: format!("Failed to read directory: {}", e),
                }
            }
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            
            // Skip hidden files
            if name.starts_with('.') {
                continue;
            }

            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };

            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            files.push(FileInfo {
                name,
                size: metadata.len(),
                is_directory: metadata.is_dir(),
                modified,
            });
        }

        // Sort by name
        files.sort_by(|a, b| a.name.cmp(&b.name));

        Response::FileList { files }
    }

    /// Handle file deletion
    async fn handle_delete(storage_dir: &Path, filename: &str) -> Response {
        let safe_filename = match validate_filename(filename) {
            Ok(f) => f,
            Err(e) => {
                return Response::Error {
                    code: ErrorCode::InvalidPath,
                    message: e.to_string(),
                }
            }
        };

        let file_path = storage_dir.join(&safe_filename);

        if !file_path.exists() {
            return Response::Error {
                code: ErrorCode::FileNotFound,
                message: format!("File not found: {}", safe_filename),
            };
        }

        if let Err(e) = fs::remove_file(&file_path).await {
            return Response::Error {
                code: ErrorCode::ServerError,
                message: format!("Failed to delete file: {}", e),
            };
        }

        info!("🗑️  Deleted file: {}", safe_filename);

        Response::Deleted {
            filename: safe_filename,
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
pub fn create_progress_bar(total_size: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}
