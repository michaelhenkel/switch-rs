#![no_std]

use core::mem;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ArpHdr {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl ArpHdr{
    pub const LEN: usize = mem::size_of::<ArpHdr>();
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpHdr {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterfaceConfig{
    pub idx: u32,
    pub mac: [u8; 6],
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceConfig {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterfaceQueue {
    pub ifidx: u32,
    pub queue: u32,
}

impl InterfaceQueue {
    pub fn new(ifidx: u32, queue: u32) -> Self {
        InterfaceQueue { ifidx, queue }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceQueue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FlowKey{
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowNextHop{
    pub ifidx: u32,
    pub queue_id: u32,
    pub src_mac: [u8;6],
    pub dst_mac: [u8;6],
    pub next_hop_count: u32,
    pub next_hop_idx: u32,
    pub packet_count: u32,
    pub active_next_hop: u32,
    pub max_packets: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowNextHop {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ArpEntry{
    pub ifidx: u32,
    pub smac: [u8;6],
    pub pad: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpEntry {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceConfiguration{
    pub vrf: u32,
    pub bridge_id: [u8;6],
    pub l2: u8,
    pub pad: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceConfiguration {}