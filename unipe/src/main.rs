use std::{
    fs,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
use unipe_common::{FlowKey, FlowRecord, HandshakeSample, HANDSHAKE_CAP};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long, default_value = "/tmp/unipe.sock")]
    socket: PathBuf,
    /// how often flows are published; this is the detection latency budget
    #[clap(long, default_value_t = 250)]
    interval_ms: u64,
    /// run the eBPF verifier over the program and exit without attaching
    #[clap(long, default_value_t = false)]
    verify: bool,
    /// attach in SKB (generic) mode, for drivers without native XDP such as wi-fi
    #[clap(long, default_value_t = false)]
    skb: bool,
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
    /// unix seconds of the last packet seen on this flow
    timestamp: f64,
    /// unix seconds of the first packet seen on this flow
    first_seen: f64,
    ttl: u8,
    icmp_type: u8,
    icmp_code: u8,
    /// bytes of DNS/TLS/QUIC handshake metadata sampled; 0 for everything else
    payload_len: u16,
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
        interval_ms,
        verify,
        skb,
    } = opt;
    let program: &mut Xdp = ebpf.program_mut("xdp_packets").unwrap().try_into()?;
    // load() is what runs the kernel verifier; attach() only wires it to a NIC
    program.load().context("eBPF verifier rejected the program")?;
    if verify {
        println!("verifier accepted xdp_packets");
        return Ok(());
    }
    let mode = if skb {
        XdpMode::Skb
    } else {
        XdpMode::default()
    };
    program
        .attach(&iface, mode)
        .context("failed to attach the XDP program - most wi-fi drivers have no native XDP, try --skb")?;

    let flows: HashMap<_, FlowKey, FlowRecord> =
        HashMap::try_from(ebpf.take_map("FLOWS").context("FLOWS map not found")?)?;
    let handshakes: HashMap<_, FlowKey, HandshakeSample> = HashMap::try_from(
        ebpf.take_map("HANDSHAKES")
            .context("HANDSHAKES map not found")?,
    )?;

    let clients = bind_flow_socket(&socket)?;
    info!(
        "flow socket listening on {} (mode 0666)",
        socket.display()
    );

    // the ebpf map stores monotonic clock values; this shifts them onto unix time
    let epoch_offset_ns = epoch_offset_ns();

    println!("Waiting for Ctrl-C...");
    let mut tick = interval(Duration::from_millis(interval_ms.max(10)));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            _ = tick.tick() => {
                match snapshot_flows(&flows, &handshakes, epoch_offset_ns) {
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
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
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

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // bpf_ktime_get_ns reads the same clock, so this lines the two up
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn epoch_offset_ns() -> u64 {
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    unix_ns.saturating_sub(monotonic_ns())
}

fn snapshot_flows(
    flows: &HashMap<aya::maps::MapData, FlowKey, FlowRecord>,
    handshakes: &HashMap<aya::maps::MapData, FlowKey, HandshakeSample>,
    epoch_offset_ns: u64,
) -> anyhow::Result<Vec<FlowExport>> {
    let mut batch = Vec::new();
    for item in flows.iter() {
        let (key, record) = item.context("failed to read flow entry")?;
        // most flows never have a handshake, so this usually misses
        let sample = handshakes.get(&key, 0).ok();
        batch.push(export_flow(key, record, sample, epoch_offset_ns));
    }
    Ok(batch)
}

fn export_flow(
    key: FlowKey,
    record: FlowRecord,
    sample: Option<HandshakeSample>,
    epoch_offset_ns: u64,
) -> FlowExport {
    let duration_ns = record.last_time_ns.saturating_sub(record.start_time_ns);
    let (payload_len, payload) = match sample {
        Some(sample) => {
            let len = sample.len.min(HANDSHAKE_CAP as u16);
            (len, hex_bytes(&sample.bytes[..len as usize]))
        }
        None => (0, String::new()),
    };
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
        timestamp: (record.last_time_ns + epoch_offset_ns) as f64 / 1_000_000_000.0,
        first_seen: (record.start_time_ns + epoch_offset_ns) as f64 / 1_000_000_000.0,
        ttl: record.ttl,
        icmp_type: record.icmp_type,
        icmp_code: record.icmp_code,
        payload_len,
        payload,
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
