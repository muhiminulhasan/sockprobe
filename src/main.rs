use clap::Parser;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// Default private allowlist (IPv4)
const DEFAULT_ALLOWLIST_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

// Special-use and restricted ranges (always blocked)
const BLOCKLIST_V4: &[&str] = &[
    "0.0.0.0/8",
    "127.0.0.0/8",     // loopback (can override with --allow-loopback)
    "169.254.0.0/16",  // link-local
    "100.64.0.0/10",   // CGNAT
    "192.0.0.0/24",
    "192.0.2.0/24",    // TEST-NET-1 (docs)
    "198.18.0.0/15",   // benchmarking
    "192.88.99.0/24",  // deprecated 6to4 relay
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // future/reserved
    "255.255.255.255/32",
];

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Finding {
    ip: String,
    port: u16,
    connect_ok: bool,
    protocol: Option<String>,
    no_auth: Option<bool>,
    userpass_offered: Option<bool>,
    userpass_success: Option<bool>,
    verified: Option<bool>,
    banner_like: Option<String>,
    latency_ms: Option<u64>,
    error: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// IP(s), CIDR(s), or range(s) like 192.168.1.10-192.168.1.250
    #[clap(long, required = true, num_args = 1..)]
    targets: Vec<String>,

    /// Port list/ranges, e.g., 1080 or 1080,1081,2000-2010
    #[clap(long, required = true)]
    ports: String,

    /// JSONL output file
    #[clap(long)]
    out: Option<String>,

    /// Concurrency level
    #[clap(long, default_value_t = 128)]
    concurrency: usize,

    /// Connect timeout in seconds
    #[clap(long, default_value_t = 2.0)]
    connect_timeout: f64,

    /// Statement: you are authorized to scan this scope
    #[clap(long, required = true)]
    attest: String,

    /// Username for user/pass auth (no brute force)
    #[clap(long)]
    user: Option<String>,

    /// Password for user/pass auth
    #[clap(long)]
    password: Option<String>,

    /// Verify via CONNECT to dest (IPv4:port) within allowed scope
    #[clap(long)]
    verify: Option<String>,

    /// Allow 127.0.0.0/8
    #[clap(long)]
    allow_loopback: bool,

    /// Allow public IPs ONLY if explicitly allowlisted with --allowlist
    #[clap(long)]
    enable_public: bool,

    /// Explicit IPv4 allowlist CIDRs (in addition to RFC1918). Required if --enable-public is set.
    #[clap(long, num_args = 0..)]
    allowlist: Vec<String>,

    /// Cap total sockets per run
    #[clap(long, default_value_t = 4096)]
    max_targets: usize,

    /// Path to blocklist YAML file
    #[clap(long)]
    blocklist_file: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Invalid IP range: {0}")]
    InvalidIPRange(String),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

fn parse_ip_item(item: &str) -> Result<HashSet<IpAddr>, Error> {
    let item = item.trim();
    let mut ips = HashSet::new();

    if item.contains('-') && !item.contains('/') {
        let parts: Vec<&str> = item.split('-').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidIPRange(item.to_string()));
        }

        let start = parts[0].trim().parse::<IpAddr>()
            .map_err(|_| Error::InvalidIPRange(item.to_string()))?;
        let end = parts[1].trim().parse::<IpAddr>()
            .map_err(|_| Error::InvalidIPRange(item.to_string()))?;

        match (start, end) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_int = u32::from(start_v4);
                let end_int = u32::from(end_v4);

                if end_int < start_int {
                    return Err(Error::InvalidIPRange(item.to_string()));
                }

                for i in start_int..=end_int {
                    ips.insert(IpAddr::V4(Ipv4Addr::from(i)));
                }
            }
            _ => return Err(Error::InvalidIPRange(item.to_string())),
        }
        return Ok(ips);
    }

    // Try CIDR
    match item.parse::<IpNetwork>() {
        Ok(network) => {
            for ip in network.iter() {
                match ip {
                    std::net::IpAddr::V4(ipv4) => { ips.insert(IpAddr::V4(ipv4)); },
                    std::net::IpAddr::V6(_) => return Err(Error::Parse("IPv6 not supported in this implementation".to_string())),
                }
            }
            Ok(ips)
        }
        Err(_) => {
            // Try single IP
            match item.parse::<IpAddr>() {
                Ok(ip) => {
                    match ip {
                        IpAddr::V4(_) => {
                            ips.insert(ip);
                            Ok(ips)
                        },
                        IpAddr::V6(_) => Err(Error::Parse("IPv6 not supported in this implementation".to_string())),
                    }
                }
                Err(_) => Err(Error::InvalidIPRange(item.to_string())),
            }
        }
    }
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, Error> {
    let mut ports = HashSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::InvalidPort(part.to_string()));
            }

            let start = range_parts[0].parse::<u16>()
                .map_err(|_| Error::InvalidPort(range_parts[0].to_string()))?;
            let end = range_parts[1].parse::<u16>()
                .map_err(|_| Error::InvalidPort(range_parts[1].to_string()))?;

            if start > end {
                return Err(Error::InvalidPort(part.to_string()));
            }

            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let p = part.parse::<u16>()
                .map_err(|_| Error::InvalidPort(part.to_string()))?;

            // Port is already u16, so it's always <= 65535

            ports.insert(p);
        }
    }

    let mut ports_vec: Vec<u16> = ports.into_iter().collect();
    ports_vec.sort();
    Ok(ports_vec)
}

fn load_networks(nets: &[String]) -> Result<Vec<IpNetwork>, Error> {
    let mut networks = Vec::new();

    for net_str in nets {
        let network = net_str.trim().parse::<IpNetwork>()
            .map_err(|_| Error::Parse(format!("Invalid network: {}", net_str)))?;

        match network {
            IpNetwork::V4(_) => networks.push(network),
            IpNetwork::V6(_) => return Err(Error::Parse("IPv6 not supported in this implementation".to_string())),
        }
    }

    Ok(networks)
}

fn load_blocklist_from_file(path: &str) -> Result<Vec<IpNetwork>, Error> {
    let file = File::open(path)
        .map_err(|e| Error::Parse(format!("Failed to open blocklist file: {}", e)))?;
    let reader = BufReader::new(file);
    let mut networks = Vec::new();

    for line in reader.lines() {
        let line = line
            .map_err(|e| Error::Parse(format!("Failed to read blocklist file: {}", e)))?
            .trim()
            .to_string();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let network = line.parse::<IpNetwork>()
            .map_err(|_| Error::Parse(format!("Invalid network in blocklist: {}", line)))?;

        match network {
            IpNetwork::V4(_) => networks.push(network),
            IpNetwork::V6(_) => return Err(Error::Parse("IPv6 not supported in this implementation".to_string())),
        }
    }

    Ok(networks)
}

fn is_in_any(ip: IpAddr, nets: &[IpNetwork]) -> bool {
    nets.iter().any(|net| net.contains(ip))
}

fn validate_targets(
    ips: HashSet<IpAddr>,
    allowlist: &[IpNetwork],
    blocklist: &[IpNetwork],
    allow_loopback: bool,
    enable_public: bool,
) -> (HashSet<IpAddr>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut valid = HashSet::new();

    for ip in ips {
        // Check loopback
        if !allow_loopback {
            if let IpAddr::V4(ipv4) = ip {
                if ipv4.is_loopback() {
                    warnings.push(format!("Blocked loopback target {} (use --allow-loopback to override)", ip));
                    continue;
                }
            }
        }

        // Check blocklist
        if is_in_any(ip, blocklist) {
            warnings.push(format!("Blocked special-use/restricted target {}", ip));
            continue;
        }

        // Allowlist logic
        if is_in_any(ip, allowlist) {
            valid.insert(ip);
            continue;
        }

        // If not in allowlist
        if enable_public {
            warnings.push(format!("Public IP {} not in explicit allowlist — blocked", ip));
            continue;
        } else {
            warnings.push(format!("Blocked non-allowlisted IP {} (enable-public not set)", ip));
            continue;
        }
    }

    (valid, warnings)
}

async fn tcp_connect(addr: SocketAddr, timeout_secs: f64) -> Result<TcpStream, Error> {
    let duration = Duration::from_secs_f64(timeout_secs);
    let stream = timeout(duration, TcpStream::connect(addr)).await
        .map_err(|_| Error::Network(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout")))??;
    Ok(stream)
}

async fn socks5_greet(
    stream: &mut TcpStream,
    allow_noauth: bool,
    have_userpass: bool,
) -> Result<Option<u8>, Error> {
    let mut methods = Vec::new();
    if allow_noauth {
        methods.push(0x00);
    }
    if have_userpass {
        methods.push(0x02);
    }

    if methods.is_empty() {
        return Ok(None);
    }

    let request = [
        vec![0x05, methods.len() as u8],
        methods,
    ].concat();

    stream.write_all(&request).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != 0x05 {
        return Ok(None);
    }

    Ok(Some(response[1])) // selected method
}

async fn socks5_userpass_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<bool, Error> {
    let u = username.as_bytes();
    let p = password.as_bytes();

    if u.len() > 255 || p.len() > 255 {
        return Ok(false);
    }

    let request = [
        vec![0x01, u.len() as u8],
        u.to_vec(),
        vec![p.len() as u8],
        p.to_vec(),
    ].concat();

    stream.write_all(&request).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    Ok(response[0] == 0x01 && response[1] == 0x00)
}

async fn socks5_verify_connect(
    stream: &mut TcpStream,
    dest_ip: &str,
    dest_port: u16,
) -> Result<bool, Error> {
    let ip: Ipv4Addr = dest_ip.parse()
        .map_err(|_| Error::Parse("Invalid destination IP".to_string()))?;
    let octets = ip.octets();

    let request = [
        vec![0x05, 0x01, 0x00, 0x01],
        octets.to_vec(),
        dest_port.to_be_bytes().to_vec(),
    ].concat();

    stream.write_all(&request).await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[0] != 0x05 {
        return Ok(false);
    }

    let rep = response[1];
    
    // Read remaining address fields (BND.ADDR + BND.PORT)
    let atyp = response[3];
    match atyp {
        0x01 => {
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).await?;
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut addr_port = vec![0u8; len + 2];
            stream.read_exact(&mut addr_port).await?;
        }
        0x04 => {
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port).await?;
        }
        _ => return Ok(false),
    }

    Ok(rep == 0x00)
}

async fn socks4_connect_verify(
    stream: &mut TcpStream,
    dest_ip: &str,
    dest_port: u16,
    user_id: &[u8],
) -> Result<(bool, String), Error> {
    let ip: Ipv4Addr = dest_ip.parse()
        .map_err(|_| Error::Parse("Invalid destination IP".to_string()))?;

    let request = [
        vec![0x04, 0x01],
        dest_port.to_be_bytes().to_vec(),
        ip.octets().to_vec(),
        user_id.to_vec(),
        vec![0x00],
    ].concat();

    stream.write_all(&request).await?;

    let mut response = [0u8; 8];
    stream.read_exact(&mut response).await?;

    if response.len() != 8 {
        return Ok((false, "short response".to_string()));
    }

    let cd = response[1];
    if cd == 90 {
        Ok((true, "OK".to_string()))
    } else {
        Ok((false, format!("CD={}", cd)))
    }
}

async fn classify_target(
    ip: IpAddr,
    port: u16,
    opts: &Opts,
) -> Result<Finding, Error> {
    let start_time = Instant::now();
    let mut finding = Finding {
        ip: ip.to_string(),
        port,
        connect_ok: false,
        protocol: None,
        no_auth: None,
        userpass_offered: None,
        userpass_success: None,
        verified: None,
        banner_like: None,
        latency_ms: None,
        error: None,
        timestamp: chrono::Utc::now(),
    };

    let addr = SocketAddr::new(ip, port);
    let mut stream = match tcp_connect(addr, opts.connect_timeout).await {
        Ok(s) => {
            finding.connect_ok = true;
            s
        }
        Err(e) => {
            finding.error = Some(format!("connect: {}", e));
            finding.latency_ms = Some(start_time.elapsed().as_millis() as u64);
            return Ok(finding);
        }
    };

    // Attempt SOCKS5 first
    let allow_noauth = true; // Always safe to advertise capability
    let have_userpass = opts.user.is_some() && opts.password.is_some();

    let selected = match socks5_greet(&mut stream, allow_noauth, have_userpass).await {
        Ok(s) => s,
        Err(_) => None,
    };

    if let Some(method) = selected {
        finding.protocol = Some("socks5".to_string());
        match method {
            0x00 => {
                finding.no_auth = Some(true);
                // Optional verify (only if provided and allowed)
                if let (Some(ref verify_ip), Some(verify_port)) = (&opts.verify_ip, &opts.verify_port) {
                    match socks5_verify_connect(&mut stream, verify_ip, *verify_port).await {
                        Ok(ok) => finding.verified = Some(ok),
                        Err(_) => {}
                    }
                }
            }
            0x02 => {
                finding.userpass_offered = Some(true);
                if have_userpass {
                    if let (Some(ref user), Some(ref password)) = (&opts.user, &opts.password) {
                        match socks5_userpass_auth(&mut stream, user, password).await {
                            Ok(ok) => {
                                finding.userpass_success = Some(ok);
                                if ok {
                                    if let (Some(ref verify_ip), Some(verify_port)) = (&opts.verify_ip, &opts.verify_port) {
                                        match socks5_verify_connect(&mut stream, verify_ip, *verify_port).await {
                                            Ok(v) => finding.verified = Some(v),
                                            Err(_) => {}
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            _ => {
                // Unsupported method
                finding.banner_like = Some(format!("socks5_requires_method_{}", method));
            }
        }
    } else {
        // Not SOCKS5; try SOCKS4/4a only if verify target is set (to avoid outbound scanning)
        stream.shutdown().await.ok();

        if opts.verify_ip.is_some() && opts.verify_port.is_some() {
            match tcp_connect(addr, opts.connect_timeout).await {
                Ok(mut stream2) => {
                    if let (Some(ref verify_ip), Some(verify_port)) = (&opts.verify_ip, &opts.verify_port) {
                        match socks4_connect_verify(&mut stream2, verify_ip, *verify_port, &[]).await {
                            Ok((ok, msg)) => {
                                if ok {
                                    finding.protocol = Some("socks4_or_4a".to_string());
                                    finding.verified = Some(true);
                                } else {
                                    finding.error = Some(format!("socks4: {}", msg));
                                }
                            }
                            Err(e) => {
                                finding.error = Some(format!("socks4_connect: {}", e));
                            }
                        }
                    }
                    stream2.shutdown().await.ok();
                }
                Err(e) => {
                    finding.error = Some(format!("socks4_connect: {}", e));
                }
            }
        } else {
            finding.error = Some("no_socks5; socks4 detection disabled (no --verify)".to_string());
        }
    }

    finding.latency_ms = Some(start_time.elapsed().as_millis() as u64);
    Ok(finding)
}

#[derive(Clone)]
struct Opts {
    connect_timeout: f64,
    user: Option<String>,
    password: Option<String>,
    verify_ip: Option<String>,
    verify_port: Option<u16>,
}

fn build_targets(ip_specs: &[String], port_spec: &str) -> Result<Vec<(IpAddr, u16)>, Error> {
    let mut ips = HashSet::new();
    for spec in ip_specs {
        ips.extend(parse_ip_item(spec)?);
    }

    let ports = parse_ports(port_spec)?;

    let mut pairs = Vec::new();
    for ip in ips {
        for port in &ports {
            pairs.push((ip, *port));
        }
    }

    Ok(pairs)
}

fn attestation_required_or_exit(attest: &str) {
    if attest.trim().len() < 8 {
        eprintln!("Refusing to run without an authorization attestation. Provide --attest \"I am authorized to test X\"");
        std::process::exit(2);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Authorization attestation gate
    attestation_required_or_exit(&args.attest);

    // Parse verify target (optional, but restricted)
    let mut verify_ip = None;
    let mut verify_port = None;
    if let Some(ref verify_str) = args.verify {
        let parts: Vec<&str> = verify_str.split(':').collect();
        if parts.len() != 2 {
            eprintln!("--verify must be IPv4:port (within allowed scope)");
            std::process::exit(2);
        }

        match parts[0].parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => verify_ip = Some(ip.to_string()),
            _ => {
                eprintln!("--verify must be IPv4:port (within allowed scope)");
                std::process::exit(2);
            }
        }

        match parts[1].parse::<u16>() {
            Ok(port) => verify_port = Some(port),
            Err(_) => {
                eprintln!("Invalid verify port");
                std::process::exit(2);
            }
        }
    }

    // Build targets
    let targets = build_targets(&args.targets, &args.ports)?;
    if targets.len() > args.max_targets {
        eprintln!(
            "Refusing to scan {} sockets (cap {}). Use --max-targets to raise with proper authorization.",
            targets.len(),
            args.max_targets
        );
        std::process::exit(2);
    }

    // Effective allowlist
    let mut allowlist_networks = Vec::new();
    for net_str in DEFAULT_ALLOWLIST_V4 {
        allowlist_networks.push(net_str.parse::<IpNetwork>()?);
    }

    if !args.allowlist.is_empty() {
        if !args.enable_public {
            println!("Note: --allowlist provided but --enable-public not set; only RFC1918 will be scanned.");
        } else {
            // Only add explicit user-provided allowlist when public scanning is enabled
            allowlist_networks.extend(load_networks(&args.allowlist)?);
        }
    }

    // Load blocklist from file if provided
    let mut blocklist_networks = Vec::new();
    for net_str in BLOCKLIST_V4 {
        blocklist_networks.push(net_str.parse::<IpNetwork>()?);
    }

    if let Some(ref blocklist_file) = args.blocklist_file {
        if Path::new(blocklist_file).exists() {
            blocklist_networks.extend(load_blocklist_from_file(blocklist_file)?);
        } else {
            eprintln!("Blocklist file {} not found", blocklist_file);
            std::process::exit(2);
        }
    }

    // Verify target must be within allowlist and not blocklisted
    if let (Some(ref v_ip), _) = (&verify_ip, verify_port) {
        let verify_ip_addr: IpAddr = v_ip.parse()?;
        if !is_in_any(verify_ip_addr, &allowlist_networks) {
            eprintln!("--verify target {} is not within allowlist; refusing.", v_ip);
            std::process::exit(2);
        }

        if is_in_any(verify_ip_addr, &blocklist_networks) && !args.allow_loopback {
            eprintln!("--verify target {} is in special-use/blocked range; refusing.", v_ip);
            std::process::exit(2);
        }
    }

    // Validate targets against allowlist and blocklist
    let ips_only: HashSet<IpAddr> = targets.iter().map(|(ip, _)| *ip).collect();
    let (valid_ips, warnings) = validate_targets(
        ips_only,
        &allowlist_networks,
        &blocklist_networks,
        args.allow_loopback,
        args.enable_public,
    );

    for warning in warnings {
        println!("[guardrail] {}", warning);
    }

    // Filter targets to valid IPs
    let targets: Vec<(IpAddr, u16)> = targets
        .into_iter()
        .filter(|(ip, _)| valid_ips.contains(ip))
        .collect();

    if targets.is_empty() {
        println!("No valid targets to scan after guardrails.");
        std::process::exit(0);
    }

    // Pack options for classify_target
    let opts = Opts {
        connect_timeout: args.connect_timeout,
        user: args.user,
        password: args.password,
        verify_ip,
        verify_port,
    };

    println!(
        "Scanning {} sockets with concurrency={}. Output: {}",
        targets.len(),
        args.concurrency,
        args.out.as_deref().unwrap_or("stdout")
    );

    // Run scan with progress bar
    let pb = indicatif::ProgressBar::new(targets.len() as u64);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")?
            .progress_chars("#>-"),
    );

    let out_file = if let Some(path) = args.out {
        Some(Arc::new(Mutex::new(Some(File::create(path)?))))
    } else {
        None
    };

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.concurrency));
    let mut tasks = Vec::new();

    let open_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let err_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for (ip, port) in targets {
        let semaphore = semaphore.clone();
        let opts = opts.clone();
        let out_file = out_file.clone();
        let pb = pb.clone();
        let open_count = open_count.clone();
        let err_count = err_count.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            // Add a small random delay to be polite
            tokio::time::sleep(tokio::time::Duration::from_millis(
                rand::random::<u64>() % 150 + 25
            )).await;

            let finding = classify_target(ip, port, &opts).await.unwrap_or_else(|e| Finding {
                ip: ip.to_string(),
                port,
                connect_ok: false,
                protocol: None,
                no_auth: None,
                userpass_offered: None,
                userpass_success: None,
                verified: None,
                banner_like: None,
                latency_ms: None,
                error: Some(format!("Unexpected error: {}", e)),
                timestamp: chrono::Utc::now(),
            });

            if finding.protocol.is_some() {
                open_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            if finding.error.is_some() {
                err_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            if let Some(file) = &out_file {
                let json = serde_json::to_string(&finding).unwrap();
                let mut file_guard = file.lock().unwrap();
                if let Some(f) = file_guard.as_mut() {
                    writeln!(f, "{}", json).ok();
                }
            } else {
                let json = serde_json::to_string(&finding).unwrap();
                println!("{}", json);
            }

            pb.inc(1);
            pb.set_message(format!(
                "open: {} err: {}",
                open_count.load(std::sync::atomic::Ordering::Relaxed),
                err_count.load(std::sync::atomic::Ordering::Relaxed)
            ));
        }));
    }

    // Wait for all tasks to complete
    futures::future::join_all(tasks).await;

    pb.finish_with_message("Scan completed");

    Ok(())
}