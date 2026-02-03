//! TLS Certificate Management Module
//!
//! This module handles all TLS-related operations including:
//! - Self-signed certificate generation (for development/testing)
//! - Loading certificates and private keys from PEM files
//! - Configuring TLS for both client and server
//!
//! ## Security Concepts:
//!
//! **TLS (Transport Layer Security)** provides:
//! 1. **Confidentiality**: Data is encrypted in transit
//! 2. **Integrity**: Data cannot be modified without detection
//! 3. **Authentication**: Server (and optionally client) identity verification
//!
//! **Certificate Chain**:
//! - Root CA → Intermediate CA → End-entity certificate
//! - For development, we use self-signed certificates (single level)
//!
//! **Key Exchange**:
//! - Modern TLS uses ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
//! - Provides Perfect Forward Secrecy (PFS)

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};
use tracing::{info, warn};

/// TLS configuration for the server
pub struct ServerTlsConfig {
    pub config: Arc<ServerConfig>,
}

/// TLS configuration for the client
pub struct ClientTlsConfig {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

/// Generated certificate and key pair
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl ServerTlsConfig {
    /// Create a new server TLS configuration from certificate and key files
    ///
    /// # Arguments
    /// * `cert_path` - Path to the PEM-encoded certificate file
    /// * `key_path` - Path to the PEM-encoded private key file
    ///
    /// # Security Notes
    /// - The private key should be protected with appropriate file permissions (600)
    /// - In production, use certificates signed by a trusted CA
    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        // Load certificates (can be a chain)
        let certs = load_certs(cert_path)?;
        info!("Loaded {} certificate(s) from {:?}", certs.len(), cert_path);

        // Load private key
        let key = load_private_key(key_path)?;
        info!("Loaded private key from {:?}", key_path);

        // Build server config with modern TLS settings
        // Using rustls defaults which include:
        // - TLS 1.2 and 1.3
        // - Strong cipher suites only
        // - No deprecated algorithms
        let config = ServerConfig::builder()
            .with_no_client_auth() // For mutual TLS, use with_client_cert_verifier
            .with_single_cert(certs, key)
            .context("Failed to build server TLS config")?;

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Create server config from PEM strings (useful for generated certs)
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let certs = load_certs_from_pem(cert_pem)?;
        let key = load_private_key_from_pem(key_pem)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build server TLS config from PEM")?;

        Ok(Self {
            config: Arc::new(config),
        })
    }
}

impl ClientTlsConfig {
    /// Create a new client TLS configuration
    ///
    /// # Arguments
    /// * `ca_cert_path` - Optional path to CA certificate for server verification
    /// * `server_name` - The expected server name (for SNI and certificate verification)
    ///
    /// # Security Notes
    /// - Server certificate verification is CRITICAL for security
    /// - Never disable certificate verification in production
    pub fn new(ca_cert_path: Option<&Path>, server_name: &str) -> Result<Self> {
        let mut root_store = RootCertStore::empty();

        if let Some(ca_path) = ca_cert_path {
            // Load custom CA certificate
            let ca_certs = load_certs(ca_path)?;
            for cert in ca_certs {
                root_store
                    .add(cert)
                    .context("Failed to add CA certificate to root store")?;
            }
            info!("Loaded custom CA certificate from {:?}", ca_path);
        } else {
            // Use system root certificates
            // In production, you might want to use webpki-roots or native-tls
            warn!("No CA certificate provided, using empty root store");
            warn!("This configuration will only work with --insecure flag");
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = ServerName::try_from(server_name.to_owned())
            .context("Invalid server name for TLS")?;

        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// Create client config from CA certificate PEM string
    pub fn from_ca_pem(ca_pem: &str, server_name: &str) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        let ca_certs = load_certs_from_pem(ca_pem)?;
        
        for cert in ca_certs {
            root_store
                .add(cert)
                .context("Failed to add CA certificate to root store")?;
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = ServerName::try_from(server_name.to_owned())
            .context("Invalid server name for TLS")?;

        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// Create an insecure client config that skips certificate verification
    ///
    /// # WARNING
    /// This should NEVER be used in production! It disables all security
    /// guarantees of TLS and makes the connection vulnerable to MITM attacks.
    pub fn insecure(server_name: &str) -> Result<Self> {
        warn!("⚠️  Creating INSECURE TLS client - certificate verification DISABLED");
        warn!("⚠️  This should NEVER be used in production!");

        // Custom certificate verifier that accepts any certificate
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth();

        let server_name = ServerName::try_from(server_name.to_owned())
            .context("Invalid server name for TLS")?;

        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }
}

/// Certificate verifier that accepts any certificate (INSECURE!)
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any certificate - THIS IS INSECURE!
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Generate a self-signed certificate for development/testing
///
/// # Security Notes
/// - Self-signed certificates should ONLY be used for development
/// - For production, obtain certificates from a trusted CA (e.g., Let's Encrypt)
/// - The generated certificate includes the common name and SANs
pub fn generate_self_signed_cert(
    common_name: &str,
    san_dns_names: &[&str],
    san_ips: &[std::net::IpAddr],
) -> Result<GeneratedCert> {
    info!("Generating self-signed certificate for: {}", common_name);

    // Generate a new key pair
    let key_pair = KeyPair::generate()
        .context("Failed to generate key pair")?;

    // Configure certificate parameters
    let mut params = CertificateParams::default();
    
    // Set the common name (CN)
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name.push(DnType::OrganizationName, "Secure File Transfer");
    
    // Add Subject Alternative Names (SANs)
    // Modern browsers require SANs and ignore CN for validation
    let mut sans = Vec::new();
    for dns_name in san_dns_names {
        sans.push(SanType::DnsName((*dns_name).try_into()?));
    }
    for ip in san_ips {
        sans.push(SanType::IpAddress(*ip));
    }
    params.subject_alt_names = sans;

    // Generate the certificate
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    info!("✓ Generated self-signed certificate");
    info!("  Subject: CN={}", common_name);
    info!("  SANs: {:?}, {:?}", san_dns_names, san_ips);

    Ok(GeneratedCert { cert_pem, key_pem })
}

/// Load certificates from a PEM file
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open certificate file: {:?}", path))?;
    let mut reader = BufReader::new(file);
    
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {:?}", path);
    }
    
    Ok(certs)
}

/// Load certificates from PEM string
fn load_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates from PEM")?;
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in PEM data");
    }
    
    Ok(certs)
}

/// Load a private key from a PEM file
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open private key file: {:?}", path))?;
    let mut reader = BufReader::new(file);
    
    let key = private_key(&mut reader)
        .context("Failed to read private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", path))?;
    
    Ok(key)
}

/// Load a private key from PEM string
fn load_private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    
    let key = private_key(&mut reader)
        .context("Failed to read private key from PEM")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in PEM data"))?;
    
    Ok(key)
}

/// Save certificate and key to files
pub fn save_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Save certificate
    fs::write(cert_path, cert_pem)
        .with_context(|| format!("Failed to write certificate to {:?}", cert_path))?;
    info!("Saved certificate to {:?}", cert_path);

    // Save private key with restricted permissions
    fs::write(key_path, key_pem)
        .with_context(|| format!("Failed to write private key to {:?}", key_path))?;
    
    // Set permissions to 600 (owner read/write only)
    let mut permissions = fs::metadata(key_path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(key_path, permissions)?;
    
    info!("Saved private key to {:?} (permissions: 600)", key_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let cert = generate_self_signed_cert(
            "localhost",
            &["localhost"],
            &["127.0.0.1".parse().unwrap()],
        )
        .unwrap();

        assert!(cert.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_server_config_from_pem() {
        let cert = generate_self_signed_cert(
            "test.local",
            &["test.local"],
            &[],
        )
        .unwrap();

        let config = ServerTlsConfig::from_pem(&cert.cert_pem, &cert.key_pem);
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_from_ca_pem() {
        let cert = generate_self_signed_cert(
            "test.local",
            &["test.local"],
            &[],
        )
        .unwrap();

        let config = ClientTlsConfig::from_ca_pem(&cert.cert_pem, "test.local");
        assert!(config.is_ok());
    }
}
