#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::{self, Icmpv4Hdr},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

use core::mem;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
fn xdp_packets(ctx: XdpContext) -> u32 {
    match try_xdp_packets(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
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

#[allow(unused)]
fn try_xdp_packets(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //(2)
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let ttl: u8 = unsafe { (*ipv4hdr).ttl };
    let length = unsafe { (*ipv4hdr).tot_len };

    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|network_types::ip::IpError::InvalidProto(_proto)| ())?;

    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut icmp_type = 0u8;
    let mut icmp_code = 0u8;

    let l7_offset = match proto {
        network_types::ip::IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + ihl)?;
            src_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            dst_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
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
        _ => return Err(()),
    };

    let payload: [u8; 64] = match ptr_at(&ctx, l7_offset) {
        Ok(ptr) => unsafe { *ptr },
        Err(()) => [0u8; 64],
    };

    Ok(xdp_action::XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
