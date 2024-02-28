#![no_std]
#![no_main]

use core::mem;
use aya_bpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_redirect_map},
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
    
};
use aya_log_ebpf::info;
use network_types::eth::{EthHdr, EtherType};
use switch_rs_common::{ArpHdr, InterfaceConfig, InterfaceQueue};

#[map(name = "INTERFACEMAP")]
static mut INTERFACEMAP: HashMap<u32, InterfaceConfig> =
    HashMap::<u32, InterfaceConfig>::with_max_entries(65535, 0);

#[map(name = "INTERFACECOUNT")]
static mut INTERFACECOUNT: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1, 0);

#[map(name = "MACTABLE")]
static mut MACTABLE: HashMap<[u8;6], u32> =
    HashMap::<[u8;6], u32>::with_max_entries(1000, 0);

#[map(name = "XSKMAP")]
static mut XSKMAP: XskMap = XskMap::with_max_entries(256, 0);

#[map(name = "INTERFACEQUEUETABLE")]
static mut INTERFACEQUEUETABLE: HashMap<InterfaceQueue, u32> =
    HashMap::<InterfaceQueue, u32>::with_max_entries(256, 0);

#[xdp]
pub fn switch_rs(ctx: XdpContext) -> u32 {
    match try_switch_rs(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_switch_rs(ctx: XdpContext) -> Result<u32, u32> {
    let ingress_if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    //info!(&ctx,"ingress_if_idx: {}", ingress_if_idx);
    let length = ctx.data_end() - ctx.data();
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_ABORTED)?;
    if unsafe { (*eth_hdr).ether_type } == EtherType::Arp {
        let arp_hdr = match ptr_at::<ArpHdr>(&ctx, EthHdr::LEN){
            Some(arp_hdr) => arp_hdr,
            None => {
                info!(&ctx,"failed to get ARP header from packet at offset {}, total len {}", EthHdr::LEN, length);
                return Ok(xdp_action::XDP_ABORTED);
            }
        };
        let smac = unsafe { (*arp_hdr).sha };
        unsafe { MACTABLE.insert(&smac, &ingress_if_idx, 0).map_err(|_| {
            info!(&ctx,"failed to insert MAC address into MACTABLE");
            xdp_action::XDP_ABORTED
        })? };

        let arp_oper = u16::from_be(unsafe { (*arp_hdr).oper });
    
        match arp_oper {
            1 => {
                
                let queue = unsafe { (*ctx.ctx).rx_queue_index };
                let queue_idx = match unsafe { INTERFACEQUEUETABLE.get(&InterfaceQueue::new(ingress_if_idx, queue))}{
                    Some(queue_idx) => queue_idx,
                    None => {
                        info!(&ctx,"failed to get queue index from INTERFACEQUEUETABLE {}/{}", ingress_if_idx, queue);
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                match unsafe { XSKMAP.redirect(*queue_idx, 0) }{
                    Ok(res) => {
                        return Ok(res);
                    },
                    Err(e) => {
                        info!(&ctx,"failed to redirect ARP request to queue {}: {}", queue, e);
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                }

                //return Ok(xdp_action::XDP_PASS);
            }
            2 => {
                let dmac = unsafe { (*arp_hdr).tha };
                let interface = match unsafe { MACTABLE.get(&dmac) }{
                    Some(interface) => interface,
                    None => {
                        info!(&ctx,"failed to get interface from MACTABLE");
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                let res = unsafe { bpf_redirect(*interface, 0)};
                return Ok(res as u32)
            }
            _ => {
                info!(&ctx,"Not an ARP operation {}", unsafe { (*arp_hdr).oper });
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }
    
    
    let queue = unsafe { (*ctx.ctx).rx_queue_index };
    let queue_idx = match unsafe { INTERFACEQUEUETABLE.get(&InterfaceQueue::new(ingress_if_idx, queue))}{
        Some(queue_idx) => queue_idx,
        None => {
            info!(&ctx,"failed to get queue index from INTERFACEQUEUETABLE {}/{}", ingress_if_idx, queue);
            return Ok(xdp_action::XDP_ABORTED);
        }
    };
    match unsafe { XSKMAP.redirect(*queue_idx, 0) }{
        Ok(res) => {
            //info!(&ctx,"received packet on intf/queue {}/{}, redirecting to queue {}",ingress_if_idx,queue, *queue_idx);
            Ok(res)
        },
        Err(e) => {
            info!(&ctx,"failed to redirect ARP request to queue {}: {}", queue, e);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
    
    
    /*
    
    let dmac = unsafe { (*eth_hdr).dst_addr };
    let interface = unsafe { MACTABLE.get(&dmac).ok_or(xdp_action::XDP_ABORTED)? };
    let res = unsafe { bpf_redirect(*interface, 0)};
    Ok(res as u32)
    */
    
    
    
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    

    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_md<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.metadata();
    let end = ctx.metadata_end();
    let len = mem::size_of::<T>();
    

    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}
