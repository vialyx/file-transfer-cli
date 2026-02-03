//! Protocol Definition Module
//!
//! This module defines the secure file transfer protocol including:
//! - Message types for client-server communication
//! - Binary framing for efficient data transfer
//! - Integrity verification using SHA-256 hashes
//!
//! ## Protocol Overview
//!
//! The protocol uses a simple request-response pattern over TLS:
//!
//! ```text
//! Client                                 Server
//!   |                                      |
//!   |-- [TLS Handshake] ------------------>|
//!   |<----------------- [TLS Established] -|
//!   |                                      |
//!   |-- UploadRequest(filename, size) ---->|
//!   |<----------------- UploadAccepted ----|
//!   |-- [File Data Chunks] --------------->|
//!   |<----------------- UploadComplete ----|
//!   |                                      |
//!   |-- DownloadRequest(filename) -------->|
//!   |<---- DownloadReady(size, hash) ------|
//!   |<----------------- [File Data] -------|
//!   |-- DownloadComplete ----------------->|
//! ```
//!
//! ## Security Features
//!
//! 1. All communication encrypted via TLS 1.2/1.3
//! 2. File integrity verified using SHA-256 checksums
//! 3. Message length prefixing prevents injection attacks
//! 4. Server validates all paths to prevent directory traversal

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size (16 MB) - prevents memory exhaustion
pub const MAX_MESSAGE_SIZE: u64 = 16 * 1024 * 1024;

/// Chunk size for file transfers (64 KB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Magic bytes to identify our protocol
pub const PROTOCOL_MAGIC: &[u8; 4] = b"SFT1";

/// Protocol errors
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(u64, u64),

    #[error("Invalid protocol magic")]
    InvalidMagic,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Transfer aborted: {0}")]
    Aborted(String),
}

/// Client-to-server request messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Request to upload a file
    Upload {
        filename: String,
        size: u64,
        sha256_hash: String,
    },

    /// Request to download a file
    Download { filename: String },

    /// List available files on server
    List { path: Option<String> },

    /// Delete a file (requires authorization)
    Delete { filename: String },

    /// Ping for connection keep-alive
    Ping,
}

/// Server-to-client response messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Upload request accepted, ready to receive data
    UploadAccepted,

    /// Upload completed successfully
    UploadComplete { bytes_received: u64 },

    /// Download ready, sending file info
    DownloadReady {
        size: u64,
        sha256_hash: String,
    },

    /// Download completed
    DownloadComplete,

    /// File listing
    FileList { files: Vec<FileInfo> },

    /// File deleted successfully
    Deleted { filename: String },

    /// Pong response to ping
    Pong,

    /// Error response
    Error { code: ErrorCode, message: String },
}

/// File information for listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified: Option<u64>, // Unix timestamp
}

/// Error codes for structured error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    FileNotFound,
    PermissionDenied,
    InvalidPath,
    StorageFull,
    HashMismatch,
    TransferAborted,
    ServerError,
}

/// Protocol message with framing
///
/// Wire format:
/// ```text
/// +----------+----------+----------+
/// | Magic(4) | Length(4)| Payload  |
/// +----------+----------+----------+
/// ```
pub struct MessageFramer;

impl MessageFramer {
    /// Write a message with length prefix
    pub async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
        T: Serialize,
    {
        let payload = serde_json::to_vec(message)?;
        let len = payload.len() as u64;

        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
        }

        // Write magic bytes
        writer.write_all(PROTOCOL_MAGIC).await?;

        // Write length as big-endian u32
        writer.write_u32(len as u32).await?;

        // Write payload
        writer.write_all(&payload).await?;
        writer.flush().await?;

        Ok(())
    }

    /// Read a message with length prefix
    pub async fn read_message<R, T>(reader: &mut R) -> Result<T, ProtocolError>
    where
        R: AsyncRead + Unpin,
        T: for<'de> Deserialize<'de>,
    {
        // Read and verify magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;

        if &magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        // Read length
        let len = reader.read_u32().await? as u64;

        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
        }

        // Read payload
        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload).await?;

        // Deserialize
        let message = serde_json::from_slice(&payload)?;

        Ok(message)
    }

    /// Write raw data chunks (for file transfer)
    pub async fn write_data<W>(writer: &mut W, data: &[u8]) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        // Write chunk length
        writer.write_u32(data.len() as u32).await?;
        // Write chunk data
        writer.write_all(data).await?;
        Ok(())
    }

    /// Read a data chunk
    pub async fn read_data<R>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        // Read chunk length
        let len = reader.read_u32().await? as usize;

        if len > buffer.len() {
            return Err(ProtocolError::InvalidFormat(format!(
                "Chunk size {} exceeds buffer size {}",
                len,
                buffer.len()
            )));
        }

        // Read chunk data
        if len > 0 {
            reader.read_exact(&mut buffer[..len]).await?;
        }

        Ok(len)
    }

    /// Write end-of-data marker
    pub async fn write_end_marker<W>(writer: &mut W) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        writer.write_u32(0).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Calculate SHA-256 hash of data
pub fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Streaming hash calculator for large files
pub struct StreamingHasher {
    hasher: Sha256,
    bytes_processed: u64,
}

impl StreamingHasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_processed: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
    }

    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }

    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate filename to prevent directory traversal attacks
///
/// # Security
/// This is a critical security function that prevents attackers from
/// accessing files outside the designated storage directory.
pub fn validate_filename(filename: &str) -> Result<String, ProtocolError> {
    // Check for empty filename
    if filename.is_empty() {
        return Err(ProtocolError::InvalidFormat("Empty filename".to_string()));
    }

    // Check for path traversal attempts
    if filename.contains("..") {
        return Err(ProtocolError::PermissionDenied(
            "Path traversal detected".to_string(),
        ));
    }

    // Check for absolute paths
    if filename.starts_with('/') || filename.starts_with('\\') {
        return Err(ProtocolError::PermissionDenied(
            "Absolute paths not allowed".to_string(),
        ));
    }

    // Check for hidden files (optional security measure)
    if filename.starts_with('.') {
        return Err(ProtocolError::PermissionDenied(
            "Hidden files not allowed".to_string(),
        ));
    }

    // Normalize path separators
    let normalized = filename.replace('\\', "/");

    // Additional check: no double slashes
    if normalized.contains("//") {
        return Err(ProtocolError::InvalidFormat(
            "Invalid path format".to_string(),
        ));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("test.txt").is_ok());
        assert!(validate_filename("folder/file.txt").is_ok());
        assert!(validate_filename("a/b/c/d.txt").is_ok());
    }

    #[test]
    fn test_validate_filename_traversal() {
        assert!(validate_filename("../etc/passwd").is_err());
        assert!(validate_filename("foo/../bar").is_err());
        assert!(validate_filename("..").is_err());
    }

    #[test]
    fn test_validate_filename_absolute() {
        assert!(validate_filename("/etc/passwd").is_err());
        assert!(validate_filename("\\Windows\\System32").is_err());
    }

    #[test]
    fn test_validate_filename_hidden() {
        assert!(validate_filename(".hidden").is_err());
        assert!(validate_filename(".ssh/config").is_err());
    }

    #[test]
    fn test_hash_calculation() {
        let hash = calculate_hash(b"Hello, World!");
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_streaming_hasher() {
        let mut hasher = StreamingHasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash = hasher.finalize();
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }
}
