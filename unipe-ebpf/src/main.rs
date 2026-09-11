#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::LruHashMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::Icmpv4Hdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
use unipe_common::{FlowKey, FlowRecord};

use core::mem;

const FLOW_MAP_SIZE: u32 = 10240;

#[map]
static FLOWS: LruHashMap<FlowKey, FlowRecord> =
    LruHashMap::with_max_entries(FLOW_MAP_SIZE, 0);

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

// returns (buf, length_copied).
#[inline(always)]
fn read_payload(ctx: &XdpContext, offset: usize) -> ([u8; 64], u8) {
    let mut buf = [0u8; 64];
    let mut len = 0u8;
    let data = ctx.data();
    let end = ctx.data_end();

    let mut i = 0usize;
    while i < 64 {
        let addr = data + offset + i;
        if addr + 1 > end {
            break;
        }
        buf[i] = unsafe { *(addr as *const u8) };
        i += 1;
        len = i as u8;
    }
    (buf, len)
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

    let (payload, payload_len) = read_payload(&ctx, l7_offset);

    let flow = FlowKey {
        src_ip: source_addr,
        dst_ip: dest_addr,
        src_port,
        dst_port,
        protocol: u8::from(proto),
        _pad: [0; 3],
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let is_dns = if src_port == 53 || dst_port == 53 { 1 } else { 0 };

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
            if (*record).payload_len == 0 && payload_len > 0 {
                (*record).payload = payload;
                (*record).payload_len = payload_len;
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
            payload,
            payload_len,
            ttl,
            icmp_type,
            icmp_code,
            is_dns,
            _pad: [0; 3],
        };
        let _ = FLOWS.insert(&flow, &record, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
