use std::{collections::HashMap, hash::Hash, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}};
use log::{error, info};
use pnet::{ipnetwork::IpNetwork, packet::{arp::{self, ArpOperations, ArpPacket, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, ip::{IpNextHeaderProtocol, IpNextHeaderProtocols}, ipv4::Ipv4Packet, Packet}};
use aya::maps::{HashMap as BpfHashMap, MapData};
use switch_rs_common::{FlowKey, FlowNextHop};
use crate::af_xdp::{af_xdp::PacketHandler, interface::interface::Interface};
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
}


impl PacketHandler for Handler {
    fn handle_packet(&mut self, buf: &mut [u8], ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>{
        if let Some(mut eth_packet) = MutableEthernetPacket::new(buf){
            info!("eth_packet: {:?}", eth_packet);
            match eth_packet.get_ethertype(){
                EtherTypes::Arp => {
                    return self.arp_handler(&mut eth_packet, ifidx, queue_id);
                },
                EtherTypes::Ipv4 => {
                    return self.ipv4_handler(eth_packet, queue_id, ifidx);
                },
                _ => {}
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
        global_flow_table: Arc<Mutex<BpfHashMap<MapData, switch_rs_common::FlowKey, switch_rs_common::FlowNextHop>>>
    ) -> Handler {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Handler{
            interface_list,
            local_mac_table: HashMap::new(),
            global_mac_table,
            global_flow_table,
            rx: Arc::new(RwLock::new(rx)),
            tx,
        }
    }
    fn arp_handler(&mut self, eth_packet: &mut MutableEthernetPacket<'_>, ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>{
        let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
        let op = arp_packet.get_operation();
        match op{
            ArpOperations::Request => {
                let mut ifidx_queue_id_list = Vec::new();
                let target_ip = arp_packet.get_target_proto_addr();
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
                info!("target_ip: {:?}", target_ip);
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
        error!("ARP operation not supported");
        None
    }
    fn ipv4_handler(&mut self, eth_packet: MutableEthernetPacket<'_>, queue_id: u32, ifidx: u32) -> Option<Vec<(u32, u32)>>{
        let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
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
                return Some(vec![(flow_next_hop.ifidx, flow_next_hop.queue_id)]);
            }

        }
        
        let dst_mac: [u8;6] = eth_packet.get_destination().into();
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
                    src_ip: u32::from_be_bytes(ip_packet.get_source().octets()),
                    dst_ip: u32::from_be_bytes(ip_packet.get_destination().octets()),
                    src_port,
                    dst_port,
                };
                let flow_next_hop = FlowNextHop{
                    ifidx: ret.as_ref().unwrap()[0].0,
                    queue_id: ret.as_ref().unwrap()[0].1,
                    mac: eth_packet.get_source().into(),
                };
                self.global_flow_table.lock().unwrap().insert(&flow_key, &flow_next_hop, 0).unwrap();
            }
            return ret
        }

        //let oif_list = route_lookup(u32::from_be_bytes(ip_packet.get_destination().octets()));
        //info!("oif_list: {:?}", oif_list);

        let mut ifidx_queue_id_list = Vec::new();
        for (_, interface) in &self.interface_list{
            if interface.ifidx == ifidx{
                continue;
            }
            ifidx_queue_id_list.push((interface.ifidx, queue_id));
        }
        self.local_mac_table.insert(eth_packet.get_source().into(), ifidx);
        return Some(ifidx_queue_id_list);
    }
}

fn route_lookup(prefix: u32) -> Vec<u32>{
    let rt = Runtime::new().unwrap();
    
    let _guard = rt.enter();
    let (connection, handle, _) = new_connection().unwrap();
    let ret = tokio::spawn(async move {
        tokio::spawn(connection);
        let mut oif_list = Vec::new();
        let mut routes = handle.route().get(IpVersion::V4).execute();
        while let Some(route_message) = routes.try_next().await.unwrap() {
            let destination_prefix_len = route_message.header.destination_prefix_length;
            for attr in &route_message.attributes {
                if let RouteAttribute::Destination(route_address) = attr{
                    if let RouteAddress::Inet(address) = route_address {
                        let ip_net = ipnet::IpNet::new(IpAddr::V4(*address), destination_prefix_len).unwrap();
                        let prefix = Ipv4Addr::from(prefix);
                        if ip_net.contains(&IpAddr::V4(prefix)){
                            for attr in &route_message.attributes {
                                match attr{
                                    RouteAttribute::Oif(oif) => {
                                        oif_list.push(*oif);
                                    },
                                    RouteAttribute::MultiPath(route_next_hop_list) => {
                                        for route_next_hop in route_next_hop_list{
                                            oif_list.push(route_next_hop.interface_index);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("oif_list: {:?}", oif_list);
        oif_list
    });
    let mut oif_list = Vec::new();
    oif_list
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