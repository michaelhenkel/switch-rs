use std::{collections::HashMap,net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}, vec};
use async_trait::async_trait;
use log::error;
use pnet::{ipnetwork::IpNetwork, packet::{arp::{ArpOperations, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, icmp::{IcmpTypes, MutableIcmpPacket}, ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, Packet}, util::MacAddr};
use aya::maps::{HashMap as BpfHashMap, MapData};
use switch_rs_common::{ArpEntry, FlowKey, FlowNextHop};
use crate::{af_xdp::{af_xdp::PacketHandler, interface::interface::Interface}, flow_manager::flow_manager::Flow, network_state::network_state::NetworkStateClient};
use rtnetlink::new_connection;
use netlink_packet_route::link::{InfoBridgePort, InfoPortData, LinkAttribute, LinkInfo};
use pnet::packet::MutablePacket;
use futures::TryStreamExt;
use crate::flow_manager::flow_manager::FlowManagerClient;
#[derive(Clone)]
pub struct Handler{
    interface_list: HashMap<u32, Interface>,
    local_mac_table: HashMap<[u8;6], u32>,
    global_mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
    global_arp_table: Arc<Mutex<BpfHashMap<MapData, [u8;4], ArpEntry>>>,
    network_state_client: NetworkStateClient,
    flow_manager_client: FlowManagerClient,
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
                    
                }
            }
        }
        None
    }
}

impl Handler {
    pub fn new(interface_list: HashMap<u32, Interface>,
        global_mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
        global_arp_table: Arc<Mutex<BpfHashMap<MapData, [u8;4], ArpEntry>>>,
        network_state_client: NetworkStateClient,
        flow_manager_client: FlowManagerClient,
    ) -> Handler {

        Handler{
            interface_list,
            local_mac_table: HashMap::new(),
            global_mac_table,
            global_arp_table,
            network_state_client,
            flow_manager_client,
        }
    }
    async fn arp_handler(&mut self, eth_packet: &mut MutableEthernetPacket<'_>, ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>{
        let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
        let op = arp_packet.get_operation();
        match op{
            ArpOperations::Request => {
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
                let bridge_id = get_interface_by_index(ifidx).await.unwrap();
                for (_, interface) in &self.interface_list{
                    if interface.ifidx == ifidx{
                        continue;
                    }
                    let if_bridge_id = get_interface_by_index(interface.ifidx).await.unwrap();
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
            if let Ok(ifidx_queue_id) = self.flow_manager_client.get_ifidx_queue(flow_key.clone()).await{
                if let Some((ifidx, queue_id)) = ifidx_queue_id{
                    self.flow_manager_client.incr_stats_packet_count(ifidx).await.unwrap();
                    self.flow_manager_client.incr_flow_packet_count(flow_key).await.unwrap();
                    return Some(vec![(ifidx, queue_id)]);
                }
            }
        }
        
        let mut ret = None;
        if let Some(dst_ifidx) = self.local_mac_table.get(&dst_mac){
            ret = Some(vec![(*dst_ifidx, queue_id)]);
        } else {
            if let Ok(dst_ifidx) = self.global_mac_table.lock().unwrap().get(&dst_mac.into(),0){
                self.local_mac_table.insert(dst_mac, dst_ifidx);
                ret = Some(vec![(dst_ifidx, queue_id)]);
            }
        };

        if ret.is_some(){
            if let Some((src_port, dst_port)) = src_dst_port{
                let flow_key = FlowKey{
                    src_ip: u32::from_be_bytes(src_ip.octets()),
                    dst_ip: u32::from_be_bytes(dst_ip.octets()),
                    src_port,
                    dst_port,
                };
                let flow_next_hop = FlowNextHop{
                    oif_idx: ret.as_ref().unwrap()[0].0,
                    queue_id,
                    src_mac,
                    dst_mac,
                    next_hop_count: 0,
                    next_hop_idx: 0,
                    packet_count: 0,
                    active_next_hop: 0,
                    max_packets: 0,
                };

                let flow = Flow{
                    key: flow_key,
                    next_hops: vec![flow_next_hop],
                };
    
                self.flow_manager_client.add_flow(flow).await.
                    unwrap_or_else(|e| error!("Failed to add flow: {}", e));
                self.flow_manager_client.incr_flow_packet_count(flow_key).await.unwrap();
            }
            self.flow_manager_client.incr_stats_packet_count(ret.as_ref().unwrap()[0].0).await.unwrap();
            return ret
        }

        let arp_entry = self.global_arp_table.lock().unwrap().get(&dst_ip.octets(), 0).ok();
        if let Some(arp_entry) = arp_entry{
            if let Some(intf) = self.network_state_client.get_interface(arp_entry.ifidx).await{
                if let Some(bridge_id) = intf.bridge_id{   
                    eth_packet.set_destination(arp_entry.smac.into());
                    eth_packet.set_source(bridge_id.into());
                    if let Some((src_port, dst_port)) = src_dst_port{
                        let flow_key = FlowKey{
                            src_ip: u32::from_be_bytes(src_ip.octets()),
                            dst_ip: u32::from_be_bytes(dst_ip.octets()),
                            src_port,
                            dst_port,
                        };

                        let flow_next_hop = FlowNextHop{
                            oif_idx: arp_entry.ifidx,
                            queue_id,
                            src_mac: bridge_id,
                            dst_mac: arp_entry.smac,
                            next_hop_count: 0,
                            next_hop_idx: 0,
                            packet_count: 0,
                            active_next_hop: 0,
                            max_packets: 0,
                        };

                        let flow = Flow{
                            key: flow_key,
                            next_hops: vec![flow_next_hop],
                        };
                    
                        self.flow_manager_client.add_flow(flow).await.
                            unwrap_or_else(|e| error!("Failed to add flow: {}", e));
                        self.flow_manager_client.incr_flow_packet_count(flow_key).await.unwrap();
                    }
                    self.flow_manager_client.incr_stats_packet_count(arp_entry.ifidx).await.unwrap();
                    return Some(vec![(arp_entry.ifidx, queue_id)]);
                }
            }
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
            let routes = self.network_state_client.get_routes(u32::from_be_bytes(dst_ip.octets()), vrf).await;
            let next_hop_count = routes.len() as u32;
            let mut ret = None;

            let mut flow = if let Some((src_port, dst_port)) = src_dst_port{
                let flow_key = FlowKey{
                    src_ip: u32::from_be_bytes(src_ip.octets()),
                    dst_ip: u32::from_be_bytes(dst_ip.octets()),
                    src_port,
                    dst_port,
                };
                let flow = Flow{
                    key: flow_key,
                    next_hops: Vec::new(),
                };
                Some(flow)
            } else {
                None
            };

            for (idx, (gateway_ip, oif_idx, mac)) in routes.iter().enumerate(){
                if let Some(gateway_mac) = self.network_state_client.get_gateway_mac_from_prefix(*gateway_ip).await{
                    eth_packet.set_destination(gateway_mac.into());
                    eth_packet.set_source(mac.clone().into());
                    let flow_next_hop = FlowNextHop{
                        oif_idx: *oif_idx,
                        queue_id,
                        src_mac: mac.clone(),
                        dst_mac: gateway_mac,
                        next_hop_count,
                        next_hop_idx: idx as u32,
                        packet_count: 0,
                        active_next_hop: 0,
                        max_packets: 10,
                    };
                    flow.as_mut().unwrap().next_hops.push(flow_next_hop);
                    ret = Some(vec![(*oif_idx, queue_id)]);
                }
            }

            if let Some(flow) = flow{
                let flow_key = flow.key;
                self.flow_manager_client.add_flow(flow).await.
                    unwrap_or_else(|e| error!("Failed to add flow: {}", e));
                if let Ok(res) = self.flow_manager_client.get_ifidx_queue(flow_key).await{
                    if let Some((ifidx, queue_id)) = res{
                        self.flow_manager_client.incr_stats_packet_count(ifidx).await.unwrap();
                        self.flow_manager_client.incr_flow_packet_count(flow_key).await.unwrap();
                        return Some(vec![(ifidx, queue_id)]);
                    }
                } else if ret.is_some(){
                    self.flow_manager_client.incr_stats_packet_count(ret.as_ref().unwrap()[0].0).await.unwrap();
                    return ret
                }
            } else if ret.is_some(){
                self.flow_manager_client.incr_stats_packet_count(ret.as_ref().unwrap()[0].0).await.unwrap();
                return ret
            }

            let bridges = self.network_state_client.get_bridges_from_vrf(vrf).await;
            for bridge in &bridges{
                for (prefix, prefix_len) in &bridge.ips{
                    let net = IpNetwork::new(IpAddr::V4(Ipv4Addr::from(*prefix)), *prefix_len).unwrap();
                    if net.contains(IpAddr::V4(Ipv4Addr::from(dst_ip))){
                        for interface in &bridge.interfaces{
                            if let Some(dst_mac) = self.network_state_client.send_arp_request(u32::from_be_bytes(dst_ip.octets()), bridge.mac, *prefix, *interface).await{
                                eth_packet.set_destination(dst_mac.into());
                                eth_packet.set_source(bridge.mac.into());
                                if let Some((src_port, dst_port)) = src_dst_port{

                                    let flow_key = FlowKey{
                                        src_ip: u32::from_be_bytes(src_ip.octets()),
                                        dst_ip: u32::from_be_bytes(dst_ip.octets()),
                                        src_port,
                                        dst_port,
                                    };

                                    let flow_next_hop = FlowNextHop{
                                        oif_idx: *interface,
                                        queue_id,
                                        src_mac: bridge.mac,
                                        dst_mac,
                                        next_hop_count,
                                        next_hop_idx: 0,
                                        packet_count: 0,
                                        active_next_hop: 0,
                                        max_packets: 0,
                                    };

                                    let flow = Flow{
                                        key: flow_key,
                                        next_hops: vec![flow_next_hop],
                                    };

                                    self.flow_manager_client.add_flow(flow).await.
                                        unwrap_or_else(|e| error!("Failed to add flow: {}", e));
                                    if let Some(res) = self.flow_manager_client.get_ifidx_queue(flow_key).await.
                                        unwrap_or_else(|e| { 
                                            error!("Failed to get ifidx_queue: {}", e);
                                            None
                                        }){
                                            self.flow_manager_client.incr_stats_packet_count(res.0).await.unwrap();
                                            self.flow_manager_client.incr_flow_packet_count(flow_key).await.unwrap();
                                            return Some(vec![(res.0, res.1)]);
                                        }
                                } else {
                                    self.flow_manager_client.incr_stats_packet_count(*interface).await.unwrap();
                                    return Some(vec![(*interface, queue_id)]);
                                }
                            }
                        }
                    }
                }
            }
        }
        error!("no forwarding information found for dst_ip: {:?}", dst_ip);
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

async fn get_interface_by_index(idx: u32)  -> Option<[u8;6]>{
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
}