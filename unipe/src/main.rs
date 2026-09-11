use std::{net::Ipv4Addr, time::Duration};

use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{signal, time::interval};
use unipe_common::{FlowKey, FlowRecord};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

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
            // This can happen if you remove all log statements from your eBPF program.
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
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("xdp_packets").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    let flows: HashMap<_, FlowKey, FlowRecord> =
        HashMap::try_from(ebpf.take_map("FLOWS").context("FLOWS map not found")?)?;

    println!("Waiting for Ctrl-C...");
    let mut tick = interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            _ = tick.tick() => {
                for item in flows.iter() {
                    let (key, record) = item.context("failed to read flow entry")?;
                    println!(
                        "{}:{} -> {}:{} proto={} pkts={} bytes={} ttl={} icmp={}/{} dns={} syn={} ack={} fin={} rst={} payload_len={}",
                        Ipv4Addr::from(key.src_ip),
                        key.src_port,
                        Ipv4Addr::from(key.dst_ip),
                        key.dst_port,
                        key.protocol,
                        record.packet_count,
                        record.byte_count,
                        record.ttl,
                        record.icmp_type,
                        record.icmp_code,
                        record.is_dns,
                        record.syn_count,
                        record.ack_count,
                        record.fin_count,
                        record.rst_count,
                        record.payload_len,
                    );
                }
            }
        }
    }

    Ok(())
}
