use std::{
    fs,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use serde::Serialize;
use tokio::{
    io::AsyncWriteExt as _,
    net::{UnixListener, UnixStream},
    signal,
    sync::Mutex,
    time::interval,
};
use unipe_common::{FlowKey, FlowRecord};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long, default_value = "/tmp/unipe.sock")]
    socket: PathBuf,
    #[clap(long, default_value_t = 2)]
    interval_secs: u64,
}

#[derive(Serialize)]
struct FlowExport {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    packets: u64,
    bytes: u64,
    duration_ms: u64,
    syn_count: u32,
    ack_count: u32,
    fin_count: u32,
    rst_count: u32,
    is_dns: bool,
    timestamp: f64,
    ttl: u8,
    icmp_type: u8,
    icmp_code: u8,
    payload_len: u8,
    payload: String,
}

type Clients = Arc<Mutex<Vec<UnixStream>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/unipe"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt {
        iface,
        socket,
        interval_secs,
    } = opt;
    let program: &mut Xdp = ebpf.program_mut("xdp_packets").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    let flows: HashMap<_, FlowKey, FlowRecord> =
        HashMap::try_from(ebpf.take_map("FLOWS").context("FLOWS map not found")?)?;

    let clients = bind_flow_socket(&socket)?;
    info!(
        "flow socket listening on {} (mode 0666)",
        socket.display()
    );

    println!("Waiting for Ctrl-C...");
    let mut tick = interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            _ = tick.tick() => {
                match snapshot_flows(&flows) {
                    Ok(batch) => {
                        if let Err(e) = publish_flows(&clients, &batch).await {
                            warn!("failed to publish flows: {e:#}");
                        }
                    }
                    Err(e) => warn!("failed to snapshot flows: {e:#}"),
                }
            }
        }
    }

    let _ = fs::remove_file(&socket);
    Ok(())
}

fn bind_flow_socket(path: &Path) -> anyhow::Result<Clients> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("failed to chmod {}", path.display()))?;

    let clients: Clients = Arc::new(Mutex::new(Vec::new()));
    let accept_clients = clients.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("python client connected");
                    accept_clients.lock().await.push(stream);
                }
                Err(e) => {
                    warn!("uds accept failed: {e}");
                }
            }
        }
    });
    Ok(clients)
}

fn snapshot_flows(
    flows: &HashMap<aya::maps::MapData, FlowKey, FlowRecord>,
) -> anyhow::Result<Vec<FlowExport>> {
    let mut batch = Vec::new();
    for item in flows.iter() {
        let (key, record) = item.context("failed to read flow entry")?;
        batch.push(export_flow(key, record));
    }
    Ok(batch)
}

fn export_flow(key: FlowKey, record: FlowRecord) -> FlowExport {
    let duration_ns = record.last_time_ns.saturating_sub(record.start_time_ns);
    let payload_len = record.payload_len.min(64);
    FlowExport {
        src_ip: Ipv4Addr::from(key.src_ip).to_string(),
        dst_ip: Ipv4Addr::from(key.dst_ip).to_string(),
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        packets: record.packet_count,
        bytes: record.byte_count,
        duration_ms: duration_ns / 1_000_000,
        syn_count: record.syn_count,
        ack_count: record.ack_count,
        fin_count: record.fin_count,
        rst_count: record.rst_count,
        is_dns: record.is_dns == 1,
        timestamp: record.last_time_ns as f64 / 1_000_000_000.0,
        ttl: record.ttl,
        icmp_type: record.icmp_type,
        icmp_code: record.icmp_code,
        payload_len,
        payload: hex_bytes(&record.payload[..payload_len as usize]),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

async fn publish_flows(clients: &Clients, batch: &[FlowExport]) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(batch).context("failed to serialize flows")?;
    let mut header = (payload.len() as u32).to_le_bytes().to_vec();
    header.extend_from_slice(&payload);

    let mut guard = clients.lock().await;
    if guard.is_empty() {
        debug!("no uds clients; skipped {} flows", batch.len());
        return Ok(());
    }

    let mut live = Vec::with_capacity(guard.len());
    for mut stream in guard.drain(..) {
        match stream.write_all(&header).await {
            Ok(()) => live.push(stream),
            Err(e) => warn!("dropping uds client: {e}"),
        }
    }
    info!("sent {} flows to {} client(s)", batch.len(), live.len());
    *guard = live;
    Ok(())
}
