use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand, ValueEnum};
use futures::future::poll_fn;
use h2::{client, server};
use http::{Request, Response};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::{self, pki_types};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "aegis-relay", version, about = "Aegis Relay System")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    Bridge(BridgeArgs),
    Destination(DestinationArgs),
}

#[derive(Args, Debug, Clone)]
struct BridgeArgs {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    #[arg(long, default_value = "127.0.0.1:9443")]
    remote: String,

    #[arg(long, default_value = "example.com")]
    sni: String,

    #[arg(long)]
    ca: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    insecure: bool,

    #[arg(long, default_value_t = 15)]
    rotate_mins: u64,

    #[arg(long, default_value_t = 512)]
    rotate_mb: u64,

    #[arg(long, default_value_t = 1200)]
    tls_fragment: usize,

    #[arg(long, value_enum, default_value_t = TlsProfile::Chrome)]
    tls_profile: TlsProfile,
}

#[derive(Args, Debug, Clone)]
struct DestinationArgs {
    #[arg(long, default_value = "0.0.0.0:9443")]
    listen: String,

    #[arg(long, default_value = "127.0.0.1:80")]
    forward: String,

    #[arg(long)]
    cert: PathBuf,

    #[arg(long)]
    key: PathBuf,

    #[arg(long, default_value_t = 1200)]
    tls_fragment: usize,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum TlsProfile {
    Chrome,
    Firefox,
    Rustls,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(cli.log_level)
        .init();

    match cli.command {
        Command::Bridge(args) => run_bridge(args).await,
        Command::Destination(args) => run_destination(args).await,
    }
}

async fn run_bridge(args: BridgeArgs) -> Result<()> {
    let listen_addr = resolve_addr(&args.listen)
        .await
        .context("resolve listen address")?;

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("bind listen socket")?;

    info!("bridge listening on {}", listen_addr);

    let config = BridgeConfig::from(args)?;
    let cycler = Arc::new(ConnectionCycler::new(config).await?);

    loop {
        let (stream, peer) = listener.accept().await?;
        let cycler = cycler.clone();
        info!("accepted local client from {}", peer);

        tokio::spawn(async move {
            if let Err(err) = handle_bridge_client(stream, cycler).await {
                warn!("bridge client error: {err:#}");
            }
        });
    }
}

async fn run_destination(args: DestinationArgs) -> Result<()> {
    let listen_addr = resolve_addr(&args.listen)
        .await
        .context("resolve listen address")?;
    let forward_addr = args.forward.clone();

    let certs = load_certs(&args.cert)?;
    let key = load_key(&args.key)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build server TLS config")?;

    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    tls_config.versions = vec![&rustls::version::TLS13];
    if args.tls_fragment > 0 {
        tls_config.max_fragment_size = Some(args.tls_fragment);
    }

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("bind destination listener")?;

    info!("destination listening on {}", listen_addr);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let forward = forward_addr.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_destination_conn(tcp, acceptor, forward).await {
                warn!("destination connection from {peer} failed: {err:#}");
            }
        });
    }
}

async fn handle_destination_conn(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    forward: String,
) -> Result<()> {
    tcp.set_nodelay(true).ok();
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut connection = server::handshake(tls).await.context("h2 handshake")?;

    while let Some(result) = connection.accept().await {
        let (request, respond) = result.context("accept h2 stream")?;
        let forward = forward.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_destination_stream(request, respond, forward).await {
                warn!("destination stream error: {err:#}");
            }
        });
    }

    Ok(())
}

async fn handle_destination_stream(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    forward: String,
) -> Result<()> {
    let response = Response::builder()
        .status(200)
        .body(())
        .context("build response")?;

    let mut send_stream = respond.send_response(response, false)?;
    let mut recv_stream = request.into_body();

    let outbound = TcpStream::connect(resolve_addr(&forward).await?).await?;
    outbound.set_nodelay(true).ok();
    let (mut outbound_read, mut outbound_write) = outbound.into_split();

    let inbound_to_outbound = recv_loop(&mut recv_stream, &mut outbound_write, None);
    let outbound_to_inbound = send_loop(&mut outbound_read, &mut send_stream, None);

    tokio::try_join!(inbound_to_outbound, outbound_to_inbound)?;

    Ok(())
}

async fn handle_bridge_client(stream: TcpStream, cycler: Arc<ConnectionCycler>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let conn = cycler.get_for_stream().await?;
    let _guard = StreamGuard::new(conn.stats.clone());

    let mut sender = conn.sender.clone();
    let request = Request::builder()
        .method("CONNECT")
        .uri("https://aegis.tunnel/")
        .header("user-agent", "Mozilla/5.0")
        .body(())
        .context("build connect request")?;

    let (response_future, mut send_stream) = sender.send_request(request, false)?;
    let response = response_future.await.context("await connect response")?;
    if response.status() != 200 {
        return Err(anyhow!("remote refused stream: {}", response.status()));
    }

    let mut recv_stream = response.into_body();
    let (mut local_read, mut local_write) = stream.into_split();

    let local_to_remote = send_loop(&mut local_read, &mut send_stream, Some(conn.stats.clone()));
    let remote_to_local = recv_loop(&mut recv_stream, &mut local_write, Some(conn.stats.clone()));

    tokio::try_join!(local_to_remote, remote_to_local)?;

    Ok(())
}

async fn send_loop<R>(
    reader: &mut R,
    send_stream: &mut h2::SendStream<Bytes>,
    stats: Option<Arc<ConnectionStats>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 16 * 1024];

    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            send_stream.send_data(Bytes::new(), true)?;
            break;
        }

        let mut offset = 0;
        send_stream.reserve_capacity(read);
        while offset < read {
            let capacity = poll_fn(|cx| send_stream.poll_capacity(cx)).await;
            let capacity = capacity.ok_or_else(|| anyhow!("send stream closed"))?;
            if capacity == 0 {
                send_stream.reserve_capacity(read - offset);
                continue;
            }
            let chunk = std::cmp::min(read - offset, capacity);
            let data = Bytes::copy_from_slice(&buf[offset..offset + chunk]);
            send_stream.send_data(data, false)?;
            offset += chunk;
            if let Some(stats) = stats.as_ref() {
                stats.bytes.fetch_add(chunk as u64, Ordering::Relaxed);
            }
        }
    }

    Ok(())
}

async fn recv_loop<W>(
    recv_stream: &mut h2::RecvStream,
    writer: &mut W,
    stats: Option<Arc<ConnectionStats>>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = recv_stream.data().await {
        let chunk = chunk.context("recv h2 data")?;
        writer.write_all(&chunk).await?;
        if let Some(stats) = stats.as_ref() {
            stats
                .bytes
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    }
    writer.shutdown().await?;
    Ok(())
}

#[derive(Clone)]
struct BridgeConfig {
    remote: String,
    sni: String,
    ca: Option<PathBuf>,
    insecure: bool,
    rotate_after: Duration,
    rotate_bytes: u64,
    tls_fragment: usize,
    tls_profile: TlsProfile,
}

impl BridgeConfig {
    fn from(args: BridgeArgs) -> Result<Self> {
        let rotate_after = Duration::from_secs(args.rotate_mins * 60);
        let rotate_bytes = args.rotate_mb.saturating_mul(1024 * 1024);

        Ok(Self {
            remote: args.remote,
            sni: args.sni,
            ca: args.ca,
            insecure: args.insecure,
            rotate_after,
            rotate_bytes,
            tls_fragment: args.tls_fragment,
            tls_profile: args.tls_profile,
        })
    }
}

struct ConnectionCycler {
    config: BridgeConfig,
    state: RwLock<CyclerState>,
}

struct CyclerState {
    active: Arc<ClientConnection>,
    draining: Vec<Arc<ClientConnection>>,
}

impl ConnectionCycler {
    async fn new(config: BridgeConfig) -> Result<Self> {
        let active = Arc::new(connect_h2_client(&config).await?);
        Ok(Self {
            config,
            state: RwLock::new(CyclerState {
                active,
                draining: Vec::new(),
            }),
        })
    }

    async fn get_for_stream(&self) -> Result<Arc<ClientConnection>> {
        let mut state = self.state.write().await;

        if state.active.should_rotate(&self.config) {
            let old = state.active.clone();
            old.stats.draining.store(true, Ordering::Relaxed);
            state.draining.push(old);

            let new_conn = Arc::new(connect_h2_client(&self.config).await?);
            state.active = new_conn;
        }

        state
            .draining
            .retain(|conn| conn.stats.active_streams.load(Ordering::Relaxed) > 0);

        state
            .active
            .stats
            .active_streams
            .fetch_add(1, Ordering::Relaxed);

        Ok(state.active.clone())
    }
}

struct ClientConnection {
    sender: client::SendRequest<Bytes>,
    stats: Arc<ConnectionStats>,
}

impl ClientConnection {
    fn should_rotate(&self, config: &BridgeConfig) -> bool {
        let too_old = config.rotate_after > Duration::from_secs(0)
            && self.stats.opened_at.elapsed() >= config.rotate_after;
        let too_big = config.rotate_bytes > 0
            && self.stats.bytes.load(Ordering::Relaxed) >= config.rotate_bytes;
        too_old || too_big
    }
}

struct ConnectionStats {
    opened_at: Instant,
    bytes: AtomicU64,
    active_streams: AtomicUsize,
    draining: std::sync::atomic::AtomicBool,
}

struct StreamGuard {
    stats: Arc<ConnectionStats>,
}

impl StreamGuard {
    fn new(stats: Arc<ConnectionStats>) -> Self {
        Self { stats }
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.stats.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn connect_h2_client(config: &BridgeConfig) -> Result<ClientConnection> {
    let io = connect_tls_stream(config).await?;

    let (sender, connection) = client::handshake(io).await.context("h2 client handshake")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!("h2 client connection error: {err:#}");
        }
    });

    let stats = Arc::new(ConnectionStats {
        opened_at: Instant::now(),
        bytes: AtomicU64::new(0),
        active_streams: AtomicUsize::new(0),
        draining: std::sync::atomic::AtomicBool::new(false),
    });

    Ok(ClientConnection { sender, stats })
}

async fn connect_tls_stream(config: &BridgeConfig) -> Result<Box<dyn AsyncReadWrite>> {
    let addr = resolve_addr(&config.remote).await?;
    let tcp = TcpStream::connect(addr).await.context("connect remote")?;
    tcp.set_nodelay(true).ok();

    match config.tls_profile {
        TlsProfile::Rustls => {
            let tls_config = build_rustls_client_config(config)?;
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
            let server_name = pki_types::ServerName::try_from(config.sni.as_str())
                .context("invalid SNI")?;
            let tls = connector.connect(server_name, tcp).await?;
            Ok(Box::new(tls))
        }
        TlsProfile::Chrome | TlsProfile::Firefox => {
            let tls = connect_boring(config, tcp).await?;
            Ok(Box::new(tls))
        }
    }
}

async fn connect_boring(
    config: &BridgeConfig,
    tcp: TcpStream,
) -> Result<tokio_boring::SslStream<TcpStream>> {
    use boring::ssl::{
        SslConnector, SslMethod, SslVerifyMode,
    };

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .context("build boring ssl connector")?;

    builder.set_verify(if config.insecure {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });

    if !config.insecure {
        if let Some(ca_path) = config.ca.as_ref() {
            let certs = load_pem_stack(ca_path)?;
            let store = builder.cert_store_mut();
            for cert in certs {
                store.add_cert(cert)?;
            }
        } else {
            builder.set_default_verify_paths()?;
        }
    }

    builder.set_alpn_protos(b"\x02h2")?;
    builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;

    if config.tls_fragment > 0 {
        builder.set_max_send_fragment(config.tls_fragment)?;
    }

    let cipher_list = match config.tls_profile {
        TlsProfile::Chrome => "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        TlsProfile::Firefox => "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        TlsProfile::Rustls => unreachable!(),
    };
    if let Err(err) = builder.set_cipher_list(cipher_list) {
        warn!("boring cipher list rejected ({err}); continuing with defaults");
    }

    let connector = builder.build();
    let ssl = connector
        .configure()?
        .into_ssl(&config.sni)?;

    let stream = tokio_boring::connect(ssl, tcp)
        .await
        .context("boring tls connect")?;

    Ok(stream)
}

fn build_rustls_client_config(config: &BridgeConfig) -> Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    if config.insecure {
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        client_config.versions = vec![&rustls::version::TLS13];
        if config.tls_fragment > 0 {
            client_config.max_fragment_size = Some(config.tls_fragment);
        }
        return Ok(client_config);
    }

    if let Some(ca_path) = config.ca.as_ref() {
        let certs = load_certs(ca_path)?;
        root_store.add_parsable_certificates(certs);
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.versions = vec![&rustls::version::TLS13];
    if config.tls_fragment > 0 {
        client_config.max_fragment_size = Some(config.tls_fragment);
    }

    Ok(client_config)
}

struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}

fn load_certs(path: &Path) -> Result<Vec<pki_types::CertificateDer<'static>>> {
    let file = File::open(path).context("open cert file")?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("read certs")?;
    Ok(certs)
}

fn load_key(path: &Path) -> Result<pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).context("open key file")?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .context("read private key")?
        .ok_or_else(|| anyhow!("no private key found"))?;
    Ok(key)
}

fn load_pem_stack(path: &Path) -> Result<Vec<boring::x509::X509>> {
    let data = std::fs::read(path)?;
    let certs = boring::x509::X509::stack_from_pem(&data)?;
    Ok(certs)
}

async fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    let mut addrs = lookup_host(addr).await.context("lookup host")?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {addr}"))
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
