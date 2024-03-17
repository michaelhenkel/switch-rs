use std::{collections::HashMap, hash::Hash, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}, vec};
use async_trait::async_trait;
use log::{error, info};
use pnet::{ipnetwork::IpNetwork, packet::{arp::{self, ArpOperations, ArpPacket, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, icmp::{IcmpTypes, MutableIcmpPacket}, ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, ipv4::{Ipv4Packet, MutableIpv4Packet}, Packet}};
use aya::maps::{HashMap as BpfHashMap, MapData};
use switch_rs_common::{FlowKey, FlowNextHop};
use crate::{af_xdp::{af_xdp::PacketHandler, interface::interface::Interface}, network_state::network_state::NetworkStateClient};
use rtnetlink::{new_connection, Error, IpVersion};
use netlink_packet_route::{
    link::{InfoBridgePort, InfoPortData, InfoPortKind, LinkAttribute, LinkInfo, LinkMessage},
    route::{RouteAddress, RouteAttribute},
};
use pnet::packet::MutablePacket;
use tokio::{runtime::{Builder, Runtime}, sync::RwLock};

use futures::{TryFutureExt, TryStreamExt};
#[derive(Clone)]
pub struct Handler{
    interface_list: HashMap<u32, Interface>,
    local_mac_table: HashMap<[u8;6], u32>,
    global_mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
    global_flow_table: Arc<Mutex<BpfHashMap<MapData, switch_rs_common::FlowKey, switch_rs_common::FlowNextHop>>>,
    rx: Arc<RwLock<tokio::sync::mpsc::UnboundedReceiver<HandlerCommand>>>,
    tx: tokio::sync::mpsc::UnboundedSender<HandlerCommand>,
    network_state_client: NetworkStateClient,
}

#[async_trait]
impl PacketHandler for Handler {
    async fn handle_packet(&mut self, buf: &mut [u8], ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>{
        if let Some(mut eth_packet) = MutableEthernetPacket::new(buf){
            match eth_packet.get_ethertype(){
                EtherTypes::Arp => {
                    return self.arp_handler(&mut eth_packet, ifidx, queue_id).await;
                },
                EtherTypes::Ipv4 => {
                    return self.ipv4_handler(&mut eth_packet, queue_id, ifidx).await;
                },
                _ => {
                    error!("ethertype not supported");
                }
            }
        }
        None
    }
}

enum HandlerCommand{
    GetBridgeForInterface{
        ifidx: u32,
        tx: tokio::sync::oneshot::Sender<Option<[u8;6]>>,
    },

}

impl Handler {
    pub async fn run(&self) -> anyhow::Result<()> {
        let mut rx = self.rx.write().await;
        while let Some(command) = rx.recv().await{
            match command{
                HandlerCommand::GetBridgeForInterface { ifidx, tx } => {
                    let bridge_id = get_interface_by_index(ifidx);
                    tx.send(bridge_id).unwrap();
                }
            }
        }
        Ok(())
    }
    pub fn new(interface_list: HashMap<u32, Interface>,
        global_mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
        global_flow_table: Arc<Mutex<BpfHashMap<MapData, switch_rs_common::FlowKey, switch_rs_common::FlowNextHop>>>,
        network_state_client: NetworkStateClient,
    ) -> Handler {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Handler{
            interface_list,
            local_mac_table: HashMap::new(),
            global_mac_table,
            global_flow_table,
            rx: Arc::new(RwLock::new(rx)),
            tx,
            network_state_client,
        }
    }
    async fn arp_handler(&mut self, eth_packet: &mut MutableEthernetPacket<'_>, ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>{
        let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
        let op = arp_packet.get_operation();
        match op{
            ArpOperations::Request => {
                info!("ARP request");
                let src_mac = arp_packet.get_sender_hw_addr();
                // add sender mac to mac table
                self.local_mac_table.insert(src_mac.into(), ifidx);

                let mut ifidx_queue_id_list = Vec::new();
                let target_ip = arp_packet.get_target_proto_addr();
                let sender_ip = arp_packet.get_sender_proto_addr();

                // check if oif for target_ip is known
                if let Some(dest_ifdx) = self.network_state_client.get_ifdx_from_ip(u32::from_be_bytes(target_ip.octets())).await{
                    ifidx_queue_id_list.push((dest_ifdx, queue_id));
                    return Some(ifidx_queue_id_list);
                }

                // check if target_ip is for us
                if let Some(bridge_id) = self.network_state_client.get_bridge_from_ip(u32::from_be_bytes(target_ip.octets())).await{
                    arp_packet.set_operation(ArpOperations::Reply);
                    arp_packet.set_sender_hw_addr(bridge_id.into());
                    arp_packet.set_sender_proto_addr(target_ip);
                    arp_packet.set_target_proto_addr(sender_ip);
                    arp_packet.set_target_hw_addr(src_mac);
                    eth_packet.set_destination(eth_packet.get_source());
                    eth_packet.set_source(bridge_id.into());
                    ifidx_queue_id_list.push((ifidx, queue_id));
                    return Some(ifidx_queue_id_list);
                }

                for (_, interface) in &self.interface_list{
                    if interface.ifidx == ifidx{
                        continue;
                    }
                    let ips = interface_ips(interface.ifidx);
                    if ips.contains(&u32::from_be_bytes(target_ip.octets())){
                        arp_packet.set_operation(ArpOperations::Reply);
                        arp_packet.set_sender_hw_addr(interface.mac.into());
                        arp_packet.set_sender_proto_addr(target_ip);
                        eth_packet.set_destination(eth_packet.get_source());
                        eth_packet.set_source(interface.mac.into());

                        ifidx_queue_id_list.push((ifidx, queue_id));
                        return Some(ifidx_queue_id_list);
                    }
                }
                let bridge_id = get_interface_by_index(ifidx);
                for (_, interface) in &self.interface_list{
                    if interface.ifidx == ifidx{
                        continue;
                    }
                    let if_bridge_id = get_interface_by_index(interface.ifidx);
                    if if_bridge_id != bridge_id{
                        continue;
                    }
                    ifidx_queue_id_list.push((interface.ifidx, queue_id));
                }
                self.local_mac_table.insert(arp_packet.get_sender_hw_addr().into(), ifidx);
                return Some(ifidx_queue_id_list);
            },
            _ => {},
        }
        None
    }
    async fn ipv4_handler(&mut self, eth_packet: &mut MutableEthernetPacket<'_>, queue_id: u32, ifidx: u32) -> Option<Vec<(u32, u32)>>{
        info!("IPv4 packet");
        let dst_mac: [u8;6] = eth_packet.get_destination().into();
        let src_mac: [u8;6] = eth_packet.get_source().into();
        let mut ip_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();
        let dst_ip = ip_packet.get_destination();
        let src_ip = ip_packet.get_source();
        let src_dst_port = match ip_packet.get_next_level_protocol(){
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = pnet::packet::tcp::TcpPacket::new(ip_packet.payload()).unwrap();
                Some((tcp_packet.get_source(), tcp_packet.get_destination()))
            },
            IpNextHeaderProtocols::Udp => {
                let udp_packet = pnet::packet::udp::UdpPacket::new(ip_packet.payload()).unwrap();
                Some((udp_packet.get_source(), udp_packet.get_destination()))
            },
            IpNextHeaderProtocols::Icmp => {

                if let Some(bridge_id) = self.network_state_client.get_bridge_from_ip(u32::from_be_bytes(dst_ip.octets())).await{
                    let mut icmp_packet = MutableIcmpPacket::new(ip_packet.payload_mut()).unwrap();
                    icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
                    icmp_packet.set_checksum(pnet::packet::icmp::checksum(&icmp_packet.to_immutable()));
                    ip_packet.set_destination(ip_packet.get_source());
                    ip_packet.set_source(dst_ip);
                    eth_packet.set_destination(eth_packet.get_source());
                    eth_packet.set_source(bridge_id.into());
                    return Some(vec![(ifidx, queue_id)]);
                }
                Some((0, 0))
            },
            _ => {
                None
            },
        };
        if let Some((src_port, dst_port)) = src_dst_port{
            let flow_key = FlowKey{
                src_ip: u32::from_be_bytes(ip_packet.get_source().octets()),
                dst_ip: u32::from_be_bytes(ip_packet.get_destination().octets()),
                src_port,
                dst_port,
            };
            if let Ok(flow_next_hop) = self.global_flow_table.lock().unwrap().get(&flow_key, 0){
                info!("found flow_next_hop: {:?}", flow_next_hop);
                return Some(vec![(flow_next_hop.ifidx, flow_next_hop.queue_id)]);
            } else {
                info!("flow_next_hop not found");
            }
        }
        
        
        let mut ret = None;
        if let Some(dst_ifidx) = self.local_mac_table.get(&dst_mac){
            info!("found dst_ififx {} in local_mac_table", dst_ifidx);
            ret = Some(vec![(*dst_ifidx, queue_id)]);
        } else {
            if let Ok(dst_ifidx) = self.global_mac_table.lock().unwrap().get(&dst_mac.into(),0){
                info!("found dst_ififx {} in global_mac_table", dst_ifidx);
                self.local_mac_table.insert(dst_mac, dst_ifidx);
                ret = Some(vec![(dst_ifidx, queue_id)]);
            }
        };

        if ret.is_some(){
            if let Some((src_port, dst_port)) = src_dst_port{
                let fwd_flow_key = FlowKey{
                    src_ip: u32::from_be_bytes(src_ip.octets()),
                    dst_ip: u32::from_be_bytes(dst_ip.octets()),
                    src_port,
                    dst_port,
                };
                let fwd_flow_next_hop = FlowNextHop{
                    ifidx: ret.as_ref().unwrap()[0].0,
                    queue_id,
                    src_mac,
                    dst_mac,
                    next_hop_count: 0,
                    next_hop_idx: 0,
                    packet_count: 0,
                };
                self.global_flow_table.lock().unwrap().insert(&fwd_flow_key, &fwd_flow_next_hop, 0).unwrap();

                let rev_flow_key = FlowKey{
                    src_ip: u32::from_be_bytes(dst_ip.octets()),
                    dst_ip: u32::from_be_bytes(src_ip.octets()),
                    src_port: dst_port,
                    dst_port: src_port,
                };
                let rev_flow_next_hop = FlowNextHop{
                    ifidx,
                    queue_id,
                    src_mac: dst_mac,
                    dst_mac: src_mac,
                    next_hop_count: 0,
                    next_hop_idx: 0,
                    packet_count: 0,
                };
                self.global_flow_table.lock().unwrap().insert(&rev_flow_key, &rev_flow_next_hop, 0).unwrap();
            }
            return ret
        }

        let vrf = if let Some(vrf) = self.network_state_client.get_vrf_from_ifidx(ifidx).await{
            Some(vrf)
        } else if let Some(intf) = self.network_state_client.get_interface(ifidx).await{
            if let Some(bridge_id) = intf.bridge_id{
                if let Some(bridge) = self.network_state_client.get_bridge(bridge_id).await{
                    bridge.vrf
                } else { None }
            } else { None }
        } else { None };
        if let Some(vrf) = vrf{
            info!("vrf: {:?}", vrf);
            let routes = self.network_state_client.get_routes(u32::from_be_bytes(dst_ip.octets()), vrf).await;
            info!("routes: {:?} for {} {:?}", routes, vrf, dst_ip);
            for (gateway_ip, oif_idx, mac) in routes{
                info!("gateway_ip: {:?}, oif_idx: {:?}, mac: {:?}", gateway_ip, oif_idx, mac);
                if let Some(gateway_mac) = self.network_state_client.get_gateway_mac_from_prefix(gateway_ip).await{
                    info!("gateway_mac: {:?}", gateway_mac);
                    eth_packet.set_destination(gateway_mac.into());
                    eth_packet.set_source(mac.into());
                    if let Some((src_port, dst_port)) = src_dst_port{
                        let fwd_flow_key = FlowKey{
                            src_ip: u32::from_be_bytes(src_ip.octets()),
                            dst_ip: u32::from_be_bytes(dst_ip.octets()),
                            src_port,
                            dst_port,
                        };
                        let fwd_flow_next_hop = FlowNextHop{
                            ifidx: oif_idx,
                            queue_id,
                            src_mac,
                            dst_mac,
                            next_hop_count: 0,
                            next_hop_idx: 0,
                            packet_count: 0,
                        };
                        self.global_flow_table.lock().unwrap().insert(&fwd_flow_key, &fwd_flow_next_hop, 0).unwrap();
        
                        let rev_flow_key = FlowKey{
                            src_ip: u32::from_be_bytes(dst_ip.octets()),
                            dst_ip: u32::from_be_bytes(src_ip.octets()),
                            src_port: dst_port,
                            dst_port: src_port,
                        };
                        let rev_flow_next_hop = FlowNextHop{
                            ifidx,
                            queue_id,
                            src_mac: dst_mac,
                            dst_mac: src_mac,
                            next_hop_count: 0,
                            next_hop_idx: 0,
                            packet_count: 0,
                        };
                        self.global_flow_table.lock().unwrap().insert(&rev_flow_key, &rev_flow_next_hop, 0).unwrap();
                    }
                    return Some(vec![(oif_idx, queue_id)]);
                }
            }
            let bridges = self.network_state_client.get_bridges_from_vrf(vrf).await;
            for bridge in &bridges{
                for (prefix, prefix_len) in &bridge.ips{
                    let net = IpNetwork::new(IpAddr::V4(Ipv4Addr::from(*prefix)), *prefix_len).unwrap();
                    if net.contains(IpAddr::V4(Ipv4Addr::from(dst_ip))){
                        info!("found bridge {:?} for dst_ip: {:?} with interfaces: {:?}",bridge, dst_ip, bridge.interfaces);
                        for interface in &bridge.interfaces{
                            info!("intf: {:?}", interface);
                            if let Some(dst_mac) = self.network_state_client.send_arp_request(u32::from_be_bytes(dst_ip.octets()), bridge.mac, *prefix, *interface).await{
                                info!("dst_mac: {:?}", dst_mac);
                                eth_packet.set_destination(dst_mac.into());
                                eth_packet.set_source(bridge.mac.into());
                                return Some(vec![(*interface, queue_id)]);
                            } else {
                                error!("dst_mac not found from arp request");
                            }
                        }
                    }
                }
            }
        }
        error!("no forwarind information found for dst_ip: {:?}", dst_ip);
        None
    }
}

fn interface_ips(idx: u32) -> Vec<u32>{
    let mut ip_list = Vec::new();
    let all_interfaces = pnet::datalink::interfaces();
    let ips = &all_interfaces.iter().find(|iface| iface.index == idx).as_ref().unwrap().ips;
    for ip in ips{
        match ip{
            IpNetwork::V4(ipv4) => {
                ip_list.push(u32::from_be_bytes(ipv4.ip().octets()));
            },
            _ => {}
        }
    }
    ip_list
}

fn get_interface_by_index(idx: u32)  -> Option<[u8;6]>{
    let rt = Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
    std::thread::spawn(move || {
        let res = rt.block_on(async move {
            let (connection, handle, _) = new_connection().unwrap();
            tokio::spawn(connection);
            let link_msg = handle.link().get().match_index(idx).execute().try_next().await.unwrap().unwrap();
            let mut bridge_id_res = None;
            for attr in &link_msg.attributes {
                if let LinkAttribute::LinkInfo(link_info_list) = attr {
                    for link_info in link_info_list {
                        if let LinkInfo::PortData(port_data) = link_info{
                            if let InfoPortData::BridgePort(bridge_port_info_list) = port_data{
                                for bridge_port_info in bridge_port_info_list{
                                    if let InfoBridgePort::BridgeId(bridge_id) = bridge_port_info{
                                        bridge_id_res = Some(bridge_id.address);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            bridge_id_res
        });
        res
    }).join().unwrap()
}