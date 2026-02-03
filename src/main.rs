//! Secure File Transfer CLI - Main Entry Point
//!
//! This CLI provides secure file transfer capabilities with TLS encryption.
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          CLI Application                                 │
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                         Commands                                    ││
//! │  │  ┌─────────┐  ┌─────────┐  ┌────────┐  ┌──────────┐  ┌──────────┐  ││
//! │  │  │  cert   │  │ server  │  │ upload │  │ download │  │   list   │  ││
//! │  │  └─────────┘  └─────────┘  └────────┘  └──────────┘  └──────────┘  ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! │                                    │                                     │
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                    TLS Layer (rustls)                               ││
//! │  │  - Certificate validation       - Perfect Forward Secrecy          ││
//! │  │  - Modern cipher suites         - TLS 1.2 / 1.3                    ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! │                                    │                                     │
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                    Protocol Layer                                   ││
//! │  │  - Message framing              - Hash verification                ││
//! │  │  - Request/Response types       - Path validation                  ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! │                                    │                                     │
//! │  ┌─────────────────────────────────────────────────────────────────────┐│
//! │  │                    Network Layer (tokio)                            ││
//! │  │  - Async TCP streams            - Connection management            ││
//! │  └─────────────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use secure_file_transfer::client::{format_size, format_timestamp, Client, ClientConfig};
use secure_file_transfer::server::{Server, ServerConfig};
use secure_file_transfer::tls::{
    generate_self_signed_cert, save_cert_and_key, ClientTlsConfig, ServerTlsConfig,
};

/// Secure File Transfer CLI
///
/// A secure file transfer tool using TLS encryption for confidential
/// and integrity-protected file transfers.
#[derive(Parser)]
#[command(name = "sft")]
#[command(author = "Maksim Vialykh")]
#[command(version = "0.1.0")]
#[command(about = "Secure File Transfer with TLS encryption", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Certificate management commands
    Cert {
        #[command(subcommand)]
        action: CertCommands,
    },

    /// Start the secure file transfer server
    Server {
        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0:8443")]
        bind: SocketAddr,

        /// Path to the server certificate (PEM)
        #[arg(long)]
        cert: PathBuf,

        /// Path to the server private key (PEM)
        #[arg(long)]
        key: PathBuf,

        /// Storage directory for files
        #[arg(short, long, default_value = "./storage")]
        storage: PathBuf,

        /// Maximum file size in MB
        #[arg(long, default_value = "1024")]
        max_size: u64,
    },

    /// Upload a file to the server
    Upload {
        /// Server address
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        hostname: String,

        /// Path to CA certificate for server verification
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Skip certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,

        /// Local file to upload
        file: PathBuf,

        /// Remote filename (defaults to local filename)
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Download a file from the server
    Download {
        /// Server address
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        hostname: String,

        /// Path to CA certificate for server verification
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Skip certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,

        /// Remote filename to download
        remote: String,

        /// Local path to save to (defaults to remote filename)
        local: Option<PathBuf>,
    },

    /// List files on the server
    List {
        /// Server address
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        hostname: String,

        /// Path to CA certificate for server verification
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Skip certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,

        /// Directory path to list
        path: Option<String>,
    },

    /// Delete a file on the server
    Delete {
        /// Server address
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        hostname: String,

        /// Path to CA certificate for server verification
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Skip certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,

        /// Filename to delete
        filename: String,
    },

    /// Test connection to server
    Ping {
        /// Server address
        #[arg(short, long, default_value = "127.0.0.1:8443")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        hostname: String,

        /// Path to CA certificate for server verification
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Skip certificate verification (INSECURE!)
        #[arg(long)]
        insecure: bool,
    },
}

#[derive(Subcommand)]
enum CertCommands {
    /// Generate a self-signed certificate for testing
    Generate {
        /// Output directory for certificate and key
        #[arg(short, long, default_value = "./certs")]
        output: PathBuf,

        /// Common name for the certificate
        #[arg(long, default_value = "localhost")]
        cn: String,

        /// Additional DNS names (comma-separated)
        #[arg(long)]
        dns: Option<String>,

        /// Additional IP addresses (comma-separated)
        #[arg(long)]
        ip: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the crypto provider (required by rustls)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Cert { action } => handle_cert_command(action).await,
        Commands::Server {
            bind,
            cert,
            key,
            storage,
            max_size,
        } => {
            run_server(bind, cert, key, storage, max_size * 1024 * 1024).await
        }
        Commands::Upload {
            server,
            hostname,
            ca,
            insecure,
            file,
            name,
        } => {
            let remote_name = name.unwrap_or_else(|| {
                file.file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "uploaded_file".to_string())
            });
            run_upload(server, &hostname, ca, insecure, &file, &remote_name).await
        }
        Commands::Download {
            server,
            hostname,
            ca,
            insecure,
            remote,
            local,
        } => {
            let local_path = local.unwrap_or_else(|| PathBuf::from(&remote));
            run_download(server, &hostname, ca, insecure, &remote, &local_path).await
        }
        Commands::List {
            server,
            hostname,
            ca,
            insecure,
            path,
        } => run_list(server, &hostname, ca, insecure, path.as_deref()).await,
        Commands::Delete {
            server,
            hostname,
            ca,
            insecure,
            filename,
        } => run_delete(server, &hostname, ca, insecure, &filename).await,
        Commands::Ping {
            server,
            hostname,
            ca,
            insecure,
        } => run_ping(server, &hostname, ca, insecure).await,
    }
}

async fn handle_cert_command(action: CertCommands) -> Result<()> {
    match action {
        CertCommands::Generate {
            output,
            cn,
            dns,
            ip,
        } => {
            info!("🔐 Generating self-signed certificate...");

            // Parse DNS names
            let dns_names: Vec<String> = dns
                .as_deref()
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec![cn.clone()]);
            let dns_refs: Vec<&str> = dns_names.iter().map(|s| s.as_str()).collect();

            // Parse IP addresses
            let ip_addrs: Vec<std::net::IpAddr> = ip
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .filter_map(|ip| ip.trim().parse().ok())
                        .collect()
                })
                .unwrap_or_else(|| vec!["127.0.0.1".parse().unwrap()]);

            // Generate certificate
            let cert = generate_self_signed_cert(&cn, &dns_refs, &ip_addrs)?;

            // Create output directory
            std::fs::create_dir_all(&output)?;

            // Save files
            let cert_path = output.join("cert.pem");
            let key_path = output.join("key.pem");

            save_cert_and_key(&cert.cert_pem, &cert.key_pem, &cert_path, &key_path)?;

            info!("✅ Certificate generated successfully!");
            info!("   Certificate: {:?}", cert_path);
            info!("   Private key: {:?}", key_path);
            info!("");
            info!("📝 Usage:");
            info!("   Server: sft server --cert {:?} --key {:?}", cert_path, key_path);
            info!("   Client: sft upload --ca {:?} <file>", cert_path);

            Ok(())
        }
    }
}

async fn run_server(
    bind: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    storage: PathBuf,
    max_file_size: u64,
) -> Result<()> {
    info!("🚀 Starting secure file transfer server...");

    let tls_config = ServerTlsConfig::from_files(&cert, &key)?;

    let config = ServerConfig {
        bind_addr: bind,
        storage_dir: storage,
        tls_config,
        max_file_size,
    };

    let server = Server::new(config);
    server.run().await
}

fn create_client_tls_config(
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
) -> Result<ClientTlsConfig> {
    if insecure {
        ClientTlsConfig::insecure(hostname)
    } else if let Some(ca_path) = ca {
        ClientTlsConfig::new(Some(&ca_path), hostname)
    } else {
        ClientTlsConfig::new(None, hostname)
    }
}

async fn run_upload(
    server: SocketAddr,
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
    file: &PathBuf,
    remote_name: &str,
) -> Result<()> {
    let tls_config = create_client_tls_config(hostname, ca, insecure)?;

    let config = ClientConfig {
        server_addr: server,
        tls_config,
    };

    let client = Client::new(config);
    let mut session = client.connect().await?;

    session.upload(file, remote_name).await
}

async fn run_download(
    server: SocketAddr,
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
    remote: &str,
    local: &PathBuf,
) -> Result<()> {
    let tls_config = create_client_tls_config(hostname, ca, insecure)?;

    let config = ClientConfig {
        server_addr: server,
        tls_config,
    };

    let client = Client::new(config);
    let mut session = client.connect().await?;

    session.download(remote, local).await
}

async fn run_list(
    server: SocketAddr,
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
    path: Option<&str>,
) -> Result<()> {
    let tls_config = create_client_tls_config(hostname, ca, insecure)?;

    let config = ClientConfig {
        server_addr: server,
        tls_config,
    };

    let client = Client::new(config);
    let mut session = client.connect().await?;

    let files = session.list(path).await?;

    if files.is_empty() {
        info!("📁 No files found");
    } else {
        info!("📁 Files on server:");
        println!();
        println!("{:<40} {:>12} {:>12}", "Name", "Size", "Modified");
        println!("{:-<66}", "");

        for file in files {
            let size = if file.is_directory {
                "<DIR>".to_string()
            } else {
                format_size(file.size)
            };

            let modified = file
                .modified
                .map(format_timestamp)
                .unwrap_or_else(|| "-".to_string());

            let name = if file.is_directory {
                format!("{}/", file.name)
            } else {
                file.name
            };

            println!("{:<40} {:>12} {:>12}", name, size, modified);
        }
    }

    Ok(())
}

async fn run_delete(
    server: SocketAddr,
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
    filename: &str,
) -> Result<()> {
    let tls_config = create_client_tls_config(hostname, ca, insecure)?;

    let config = ClientConfig {
        server_addr: server,
        tls_config,
    };

    let client = Client::new(config);
    let mut session = client.connect().await?;

    session.delete(filename).await
}

async fn run_ping(
    server: SocketAddr,
    hostname: &str,
    ca: Option<PathBuf>,
    insecure: bool,
) -> Result<()> {
    let tls_config = create_client_tls_config(hostname, ca, insecure)?;

    let config = ClientConfig {
        server_addr: server,
        tls_config,
    };

    let client = Client::new(config);
    let mut session = client.connect().await?;

    session.ping().await
}
