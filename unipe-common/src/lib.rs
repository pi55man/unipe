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
/// Sized for unidirectional IDS: TCP flag counts, ICMP type/code, and the
/// first-packet TTL. Small enough to build on the eBPF stack.
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
    pub ttl: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub is_dns: u8,
    pub _pad: [u8; 4],
}

/// Bytes of L7 handshake metadata sampled per flow.
///
/// Covers a full MTU-sized segment, so any TLS ClientHello that fits in one TCP
/// segment is captured whole, which is what JA3 needs. Must stay a power of
/// two: the eBPF copy loop masks its index with `HANDSHAKE_CAP - 1` to prove to
/// the verifier that the write is in range.
pub const HANDSHAKE_CAP: usize = 2048;

/// The cleartext head of a DNS message or a TLS/QUIC handshake record.
///
/// Kept in its own map rather than inside `FlowRecord` for two reasons: most
/// flows never have one, so bundling it would waste memory on every entry, and
/// keeping it separate makes it structural that only handshakes are ever
/// copied. Application data is never sampled.
///
/// Far too large for the 512-byte eBPF stack, so the XDP program fills one of
/// these in a per-CPU scratch map before copying it into the handshake map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandshakeSample {
    pub bytes: [u8; HANDSHAKE_CAP],
    pub len: u16,
    pub _pad: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowRecord {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HandshakeSample {}
