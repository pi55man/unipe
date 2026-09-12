#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::Icmpv4Hdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use unipe_common::{FlowKey, FlowRecord, HandshakeSample, HANDSHAKE_CAP};

use core::mem;

const FLOW_MAP_SIZE: u32 = 10240;
/// Only a small share of flows ever carry a handshake, so this map is far
/// smaller than FLOWS even though each entry is much bigger.
const HANDSHAKE_MAP_SIZE: u32 = 2048;
const DNS_PORT: u16 = 53;
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
/// First byte of a QUIC Initial: 1 = long header, 1 = fixed bit, 00 = Initial.
const QUIC_INITIAL_MASK: u8 = 0xF0;
const QUIC_INITIAL_BITS: u8 = 0xC0;

#[map]
static FLOWS: LruHashMap<FlowKey, FlowRecord> =
    LruHashMap::with_max_entries(FLOW_MAP_SIZE, 0);

#[map]
static HANDSHAKES: LruHashMap<FlowKey, HandshakeSample> =
    LruHashMap::with_max_entries(HANDSHAKE_MAP_SIZE, 0);

/// A HandshakeSample is ~2 KB, which dwarfs the 512-byte eBPF stack, so samples
/// are assembled here and then copied into HANDSHAKES. One slot per CPU, and
/// XDP runs to completion without preemption, so there is nothing to race with.
#[map]
static SCRATCH: PerCpuArray<HandshakeSample> = PerCpuArray::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
fn xdp_packets(ctx: XdpContext) -> u32 {
    match try_xdp_packets(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Copies up to HANDSHAKE_CAP L7 bytes straight into a map value and returns
/// how many were available. Writing into the map avoids ever holding the sample
/// on the stack.
#[inline(always)]
fn read_payload_into(ctx: &XdpContext, offset: usize, buf: &mut [u8; HANDSHAKE_CAP]) -> u16 {
    let data = ctx.data();
    let end = ctx.data_end();

    let mut len = 0usize;
    while len < HANDSHAKE_CAP {
        let addr = data + offset + len;
        if addr + 1 > end {
            break;
        }
        // the mask is what proves to the verifier that the index is in range
        buf[len & (HANDSHAKE_CAP - 1)] = unsafe { *(addr as *const u8) };
        len += 1;
    }
    len as u16
}

/// Only DNS messages and TLS/QUIC handshake records are worth sampling, and
/// they are the only L7 bytes we are willing to copy. Application data, which
/// is what would carry actual user content, is never touched.
#[inline(always)]
fn is_sampleable(
    ctx: &XdpContext,
    offset: usize,
    proto: IpProto,
    src_port: u16,
    dst_port: u16,
) -> bool {
    if src_port == DNS_PORT || dst_port == DNS_PORT {
        return true;
    }
    let Ok(first) = ptr_at::<u8>(ctx, offset) else {
        return false;
    };
    let byte = unsafe { *first };
    match proto {
        IpProto::Tcp => byte == TLS_HANDSHAKE_RECORD,
        // QUIC Initial: long header bit, the mandatory fixed bit, and packet
        // type 0. Deliberately not port-gated, because malware hiding QUIC on
        // an odd port is exactly what we want to catch, and this shape check is
        // tight enough that ordinary UDP does not trip it.
        IpProto::Udp => byte & QUIC_INITIAL_MASK == QUIC_INITIAL_BITS,
        _ => false,
    }
}

fn try_xdp_packets(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let ttl: u8 = unsafe { (*ipv4hdr).ttl };
    let byte_len = unsafe { (*ipv4hdr).tot_len() } as u64;

    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|network_types::ip::IpError::InvalidProto(_proto)| ())?;

    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut icmp_type = 0u8;
    let mut icmp_code = 0u8;
    let mut syn = 0u32;
    let mut ack = 0u32;
    let mut fin = 0u32;
    let mut rst = 0u32;

    let l7_offset = match proto {
        network_types::ip::IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + ihl)?;
            src_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            dst_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
            syn = unsafe { (*tcphdr).syn() } as u32;
            ack = unsafe { (*tcphdr).ack() } as u32;
            fin = unsafe { (*tcphdr).fin() } as u32;
            rst = unsafe { (*tcphdr).rst() } as u32;
            let doff = unsafe { (*tcphdr).doff() };
            EthHdr::LEN + ihl + (doff as usize) * 4
        }
        network_types::ip::IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + ihl)?;
            src_port = unsafe { (*udphdr).src_port() };
            dst_port = unsafe { (*udphdr).dst_port() };
            EthHdr::LEN + ihl + UdpHdr::LEN
        }
        network_types::ip::IpProto::Icmp => {
            let icmphdr: *const Icmpv4Hdr = ptr_at(&ctx, EthHdr::LEN + ihl)?;
            icmp_type = unsafe { (*icmphdr).type_ };
            icmp_code = unsafe { (*icmphdr).code };
            EthHdr::LEN + ihl + Icmpv4Hdr::LEN
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let sampleable = is_sampleable(&ctx, l7_offset, proto, src_port, dst_port);

    let flow = FlowKey {
        src_ip: source_addr,
        dst_ip: dest_addr,
        src_port,
        dst_port,
        protocol: u8::from(proto),
        _pad: [0; 3],
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let is_dns = if src_port == DNS_PORT || dst_port == DNS_PORT {
        1
    } else {
        0
    };

    if let Some(record) = FLOWS.get_ptr_mut(&flow) {
        unsafe {
            (*record).packet_count += 1;
            (*record).byte_count += byte_len;
            (*record).last_time_ns = now;
            (*record).syn_count += syn;
            (*record).ack_count += ack;
            (*record).fin_count += fin;
            (*record).rst_count += rst;
            if is_dns == 1 {
                (*record).is_dns = 1;
            }
        }
    } else {
        let record = FlowRecord {
            packet_count: 1,
            byte_count: byte_len,
            start_time_ns: now,
            last_time_ns: now,
            syn_count: syn,
            ack_count: ack,
            fin_count: fin,
            rst_count: rst,
            ttl,
            icmp_type,
            icmp_code,
            is_dns,
            _pad: [0; 4],
        };
        let _ = FLOWS.insert(&flow, &record, 0);
        // new or recycled 5-tuple: drop any leftover handshake for this key
        let _ = HANDSHAKES.remove(&flow);
    }

    // keep watching until a handshake shows up, then sample it exactly once
    if sampleable && HANDSHAKES.get_ptr(&flow).is_none() {
        if let Some(sample) = SCRATCH.get_ptr_mut(0) {
            unsafe {
                (*sample).len = read_payload_into(&ctx, l7_offset, &mut (*sample).bytes);
                (*sample)._pad = [0; 6];
                if (*sample).len > 0 {
                    let _ = HANDSHAKES.insert(&flow, &*sample, 0);
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
