#![no_std]

/// 5-tuple identifying a flow (map key / `record.key` in userspace).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

/// Per-flow counters and metadata (map value / `record` fields in userspace).
///
/// Sized for unidirectional IDS: TCP flag counts, ICMP type/code, first-packet
/// TTL, and a sample of the first L7 bytes seen on the flow.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowRecord {
    pub packet_count: u64,
    pub byte_count: u64,
    pub start_time_ns: u64,
    pub last_time_ns: u64,
    pub syn_count: u32,
    pub ack_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub payload: [u8; 64],
    pub payload_len: u8,
    pub ttl: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub is_dns: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowRecord {}
