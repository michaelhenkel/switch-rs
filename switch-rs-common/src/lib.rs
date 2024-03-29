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