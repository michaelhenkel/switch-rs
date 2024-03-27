#![no_std]
#![no_main]

use core::mem;
use aya_bpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_csum_diff},
    macros::{map, xdp},
    maps::{HashMap, XskMap},
    programs::XdpContext,
    
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use switch_rs_common::{
    ArpHdr,
    InterfaceConfig,
    InterfaceQueue,
    FlowKey,
    FlowNextHop,
    ArpEntry,
    InterfaceConfiguration,
    InterfaceStats
};

#[map(name = "INTERFACEMAP")]
static mut INTERFACEMAP: HashMap<u32, InterfaceConfig> =
    HashMap::<u32, InterfaceConfig>::with_max_entries(65535, 0);

#[map(name = "INTERFACECOUNT")]
static mut INTERFACECOUNT: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1, 0);

#[map(name = "MACTABLE")]
static mut MACTABLE: HashMap<[u8;6], u32> =
    HashMap::<[u8;6], u32>::with_max_entries(1000, 0);

#[map(name = "ARPTABLE")]
static mut ARPTABLE: HashMap<[u8;4], ArpEntry> =
    HashMap::<[u8;4], ArpEntry>::with_max_entries(1000, 0);

#[map(name = "XSKMAP")]
static mut XSKMAP: XskMap = XskMap::with_max_entries(256, 0);

#[map(name = "INTERFACEQUEUETABLE")]
static mut INTERFACEQUEUETABLE: HashMap<InterfaceQueue, u32> =
    HashMap::<InterfaceQueue, u32>::with_max_entries(256, 0);

#[map(name = "INTERFACECONFIGURATION")]
static mut INTERFACECONFIGURATION: HashMap<u32, InterfaceConfiguration> =
    HashMap::<u32, InterfaceConfiguration>::with_max_entries(256, 0);

#[map(name = "INTERFACESTATS")]
static mut INTERFACESTATS: HashMap<u32, InterfaceStats> =
    HashMap::<u32, InterfaceStats>::with_max_entries(256, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(65535, 0);

#[map(name = "ECNMARKERTABLE")]
static mut ECNMARKERTABLE: HashMap<FlowKey, u8> =
    HashMap::<FlowKey, u8>::with_max_entries(65535, 0);

#[xdp]
pub fn switch_rs(ctx: XdpContext) -> u32 {
    match try_switch_rs(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_switch_rs(ctx: XdpContext) -> Result<u32, u32> {
    let ingress_if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let queue = unsafe { (*ctx.ctx).rx_queue_index };
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0).ok_or(xdp_action::XDP_ABORTED)?;
    if unsafe { (*eth_hdr).ether_type } == EtherType::Arp {
        let smac = unsafe { (*eth_hdr).src_addr };
        let interface_configuration = match unsafe { INTERFACECONFIGURATION.get(&ingress_if_idx) }{
            Some(interface_configuration) => interface_configuration,
            None => {
                info!(&ctx,"failed to get interface configuration from INTERFACECONFIGURATION");
                return Ok(xdp_action::XDP_ABORTED);
            }
        };

        let arp_hdr = match ptr_at::<ArpHdr>(&ctx, EthHdr::LEN){
            Some(arp_hdr) => arp_hdr,
            None => {
                info!(&ctx,"failed to get ARP header from packet at offset {}", EthHdr::LEN);
                return Ok(xdp_action::XDP_ABORTED);
            }
        };

        if interface_configuration.l2 == 1 {
            unsafe { MACTABLE.insert(&smac, &ingress_if_idx, 0).map_err(|_| {
                info!(&ctx,"failed to insert MAC address into MACTABLE");
                xdp_action::XDP_ABORTED
            })? };
            unsafe { ARPTABLE.insert(&(*arp_hdr).spa, &ArpEntry{
                ifidx: ingress_if_idx,
                smac,
                pad: 0,
            }, 0).map_err(|_| {
                info!(&ctx,"failed to insert ARP entry into ARPTABLE");
                xdp_action::XDP_ABORTED
            })? };
        }
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { (*eth_hdr).ether_type } == EtherType::Ipv4 {
        let flowlet_packets = unsafe { INTERFACESTATS.get_ptr_mut(&ingress_if_idx) }.map(|interface_stats|{
            unsafe { 
                (*interface_stats).rx_packets += 1;
                (*interface_stats).flowlet_packets += 1;
                (*interface_stats).flowlet_packets
            }
        });

        let ipv4_hdr = match ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN){
            Some(ipv4_hdr) => ipv4_hdr,
            None => {
                info!(&ctx,"failed to get IPv4 header from packet at offset {}", EthHdr::LEN);
                return Ok(xdp_action::XDP_ABORTED);
            }
        };
        //unsafe { (*ipv4_hdr).tos = u8::to_be(1) };
        let ip_proto = unsafe { (*ipv4_hdr).proto };
        let source_dest_port = match ip_proto{
            IpProto::Tcp => {
                let tcp_hdr = match ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN){
                    Some(tcp_hdr) => tcp_hdr,
                    None => {
                        info!(&ctx,"failed to get TCP header from packet at offset {}", EthHdr::LEN + Ipv4Hdr::LEN);
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                let src_port = unsafe { (*tcp_hdr).source };
                let dst_port = unsafe { (*tcp_hdr).dest };
                Some((src_port, dst_port))
            },
            IpProto::Udp => {
                let udp_hdr = match ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN){
                    Some(udp_hdr) => udp_hdr,
                    None => {
                        info!(&ctx,"failed to get UDP header from packet at offset {}", EthHdr::LEN + Ipv4Hdr::LEN);
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };
                let src_port = unsafe { (*udp_hdr).source };
                let dst_port = unsafe { (*udp_hdr).dest };
                Some((src_port, dst_port))
            },
            IpProto::Icmp => {
                Some((0, 0))
            },
            _ => None,
        };
        if let Some((source, dest)) = source_dest_port{
            let flow_key = FlowKey{
                src_ip: u32::from_be(unsafe { (*ipv4_hdr).src_addr }),
                dst_ip: u32::from_be(unsafe { (*ipv4_hdr).dst_addr }),
                src_port: u16::from_be(source),
                dst_port: u16::from_be(dest),
            };
            if let Some(flow_next_hop) = unsafe { FLOWTABLE.get_ptr_mut(&flow_key) }{  
                for i in 0..6{
                    unsafe { (*eth_hdr).src_addr[i] = (*flow_next_hop).src_mac[i] };
                    unsafe { (*eth_hdr).dst_addr[i] = (*flow_next_hop).dst_mac[i] };
                }
                unsafe { (*flow_next_hop).packet_count += 1 };
                let ifidx = unsafe { (*flow_next_hop).oif_idx };
                unsafe { INTERFACESTATS.get_ptr_mut(&ifidx) }.map(|interface_stats|{
                    unsafe { (*interface_stats).tx_packets += 1 };
                });
                
                let send_ecn = if unsafe{ (*flow_next_hop).ecn == 1}{
                    unsafe{ (*flow_next_hop).ecn = 0 };
                    true
                } else {
                    false
                };
            
                let interface_configuration = match unsafe { INTERFACECONFIGURATION.get(&ingress_if_idx) }{
                    Some(interface_configuration) => interface_configuration,
                    None => {
                        info!(&ctx,"failed to get interface configuration from INTERFACECONFIGURATION");
                        return Ok(xdp_action::XDP_ABORTED);
                    }
                };

                if interface_configuration.l2 == 1 {
                    if let Some(flowlet_packets) = flowlet_packets{
                        let flowlet_size = interface_configuration.flowlet_size;
                        if flowlet_packets > 0 && flowlet_packets >= flowlet_size{
                            unsafe { (*ipv4_hdr).check = 0};
                            unsafe { (*ipv4_hdr).tos = 0x03 };
                            let csum = _csum(ipv4_hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
                            unsafe { (*ipv4_hdr).check = csum };
                            unsafe { INTERFACESTATS.get_ptr_mut(&ingress_if_idx) }.map(|interface_stats|{
                                unsafe { (*interface_stats).ecn_marked += 1 };
                                unsafe { (*interface_stats).flowlet_packets = 0; };
                            });
                        }
                    }
                }
                if send_ecn{
                    unsafe { (*ipv4_hdr).check = 0};
                    unsafe { (*ipv4_hdr).tos = 0x03 };
                    let csum = _csum(ipv4_hdr as *mut u32, Ipv4Hdr::LEN as u32, 0);
                    unsafe { (*ipv4_hdr).check = csum };
                    unsafe { INTERFACESTATS.get_ptr_mut(&ingress_if_idx) }.map(|interface_stats|{
                        unsafe { (*interface_stats).ecn_marked += 1 };
                    });
                }
                let res = unsafe { bpf_redirect(ifidx, 0)};
                return Ok(res as u32)
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
    info!(ctx, "trying to get metadata");
    let start = unsafe { (*ctx.ctx).data } as usize;
    let end = unsafe { (*ctx.ctx).data_meta } as usize;
    let len = mem::size_of::<T>();
    info!(ctx, "got metadata");


    if start + offset + len > end {
        info!(ctx, "returning None");
        return None;
    }
    info!(ctx, "returning metadata");
    Some((start + offset) as *const T)
}

#[inline(always)]
fn _csum(data_start: *mut u32, data_size: u32, csum: u32) -> u16 {
    let cs = unsafe { bpf_csum_diff(0 as *mut u32, 0, data_start, data_size, csum) };
    _csum_fold_helper(cs)
}

#[inline(always)]
fn _csum_fold_helper(csum: i64) -> u16 {
    let mut sum = csum;
    for _ in 0..4 {
        if sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !sum as u16
}