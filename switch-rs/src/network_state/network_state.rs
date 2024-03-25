use std::{collections::{HashMap, HashSet}, fmt::Display, net::{IpAddr, Ipv4Addr}, sync::{Arc, Mutex}};

use aya::maps::{HashMap as BpfHashMap, MapData};
use futures::TryStreamExt;
use log::info;
use netlink_packet_route::{address, link::{InfoBridgePort, InfoPortData, InfoPortKind, LinkAttribute, LinkInfo}, route::{RouteAddress, RouteAttribute}, AddressFamily};
use pnet::{datalink::{self, Channel, Config, NetworkInterface}, packet::{arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, Packet}, util::MacAddr};
use rtnetlink::{new_connection, IpVersion};
use switch_rs_common::InterfaceConfiguration;
use tokio::sync::RwLock;
use pnet::packet::MutablePacket;

use crate::af_xdp::interface::interface::Interface;


#[derive(Debug, Default, Clone)]
struct State{
    bridges: HashMap<[u8;6],NetlinkBridge>,
    ip_to_bridge: HashMap<u32,[u8;6]>,
    interfaces: HashMap<u32,NetlinkInterface>,
    mac_to_ifidx: HashMap<[u8;6],u32>,
    ifidx_to_mac: HashMap<u32,[u8;6]>,
    ip_to_mac: HashMap<u32,[u8;6]>,
    ip_to_ifidx: HashMap<u32,u32>,
    ifidx_to_vrf: HashMap<u32,u32>,
    routes: HashMap<u32, NetlinkRouteList>,
    gateway_mac_table: HashMap<u32, [u8;6]>,
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkRouteList(Vec<HashMap<u32, Vec<(u32, u32, [u8; 6])>>>);

impl Display for NetlinkRouteList{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix_len, prefix_map) in self.0.iter().enumerate(){
            for (prefix, route_list) in prefix_map{
                for route in route_list{
                    write!(f, "prefix_len: {} prefix: {} gw: {:?}, oif: {}, oif mac {:?}", prefix_len, Ipv4Addr::from(*prefix), Ipv4Addr::from(route.0), route.1, MacAddr::from(route.2))?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkBridge{
    pub ips: Vec<(u32,u8)>,
    pub idx: u32,
    pub interfaces: HashSet<u32>,
    pub vrf: Option<u32>,
    pub mac: [u8;6],
}

impl Display for NetlinkBridge{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ip_string = String::new();
        for (ip, prefix) in &self.ips{
            ip_string.push_str(&format!("{}/{} ", Ipv4Addr::from(*ip), prefix));
        }
        write!(f, "idx: {} mac: {:?} ips: {:?} vrf: {:?}", self.idx, MacAddr::from(self.mac), ip_string, self.vrf)
    }
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkInterface{
    pub mac: [u8;6],
    pub idx: u32,
    pub ips: Vec<(u32,u8)>,
    pub bridge_id: Option<[u8;6]>,
    pub vrf: Option<u32>,
}

impl Display for NetlinkInterface{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ip_string = String::new();
        for (ip, prefix) in &self.ips{
            ip_string.push_str(&format!("{}/{} ", Ipv4Addr::from(*ip), prefix));
        }
        write!(f, "idx: {} mac: {:?} ips: {:?} bridge_id: {:?} vrf: {:?}", self.idx, MacAddr::from(self.mac), ip_string, MacAddr::from(self.bridge_id.unwrap_or_default()), self.vrf)
    }
}

pub struct NetworkState{
    rx: Arc<RwLock<tokio::sync::mpsc::Receiver<NetworkStateCommand>>>,
    client: NetworkStateClient,
    global_interface_configuration: Arc<Mutex<BpfHashMap<MapData, u32, InterfaceConfiguration>>>,
    interface_list: HashMap<u32, Interface>,
    state: State,
}

impl NetworkState{
    pub fn new(interface_list: HashMap<u32, Interface>, global_interface_configuration: Arc<Mutex<BpfHashMap<MapData, u32, InterfaceConfiguration>>>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let client = NetworkStateClient::new(tx);
        Self{
            rx: Arc::new(RwLock::new(rx)),
            client,
            global_interface_configuration,
            interface_list,
            state: State::default(),
        }
    }
    pub fn client(&self) -> NetworkStateClient{
        self.client.clone()
    }
    pub async fn run(&mut self){
        for (ifidx, _) in &self.interface_list{
            let addresses = get_ip_addresses_from_ifidx(*ifidx).await;
            let mac = get_mac_address_from_ifidx(*ifidx).await;
            let vrf = get_vrf_from_ifidx(*ifidx).await;
            let mut interface = NetlinkInterface::default();
            let mut interface_configuration = InterfaceConfiguration::default();
            for (ip, _) in &addresses{
                self.state.ip_to_ifidx.insert(*ip, *ifidx);
                self.state.ip_to_mac.insert(*ip, mac);
            }
            interface.ips = addresses;
            interface.idx = *ifidx;
            interface.mac = mac;
            interface.vrf = vrf;
            if let Some(vrf) = vrf{
                self.state.ifidx_to_vrf.insert(*ifidx, vrf);
                interface_configuration.vrf = vrf;
            }
            
            let bridge_id = get_bridge_id_from_ifidx(*ifidx).await;
            if let Some(bridge_id) = bridge_id{
                interface.bridge_id = Some(bridge_id);
                interface_configuration.bridge_id = bridge_id;
                interface_configuration.l2 = 1;
                if let Some(bridge) = self.state.bridges.get_mut(&bridge_id){
                    bridge.interfaces.insert(*ifidx);
                } else {
                    let bridge_idx = get_ifidx_from_mac(bridge_id).await.unwrap();
                    let addresses = get_ip_addresses_from_ifidx(bridge_idx).await;
                    let vrf = get_vrf_from_ifidx(bridge_idx).await;
                    for (address, _) in &addresses{
                        self.state.ip_to_bridge.insert(*address, bridge_id);
                        self.state.ip_to_mac.insert(*address, bridge_id);
                    }
                    let mut bridge = NetlinkBridge::default();
                    bridge.ips = addresses;
                    bridge.idx = bridge_idx;
                    bridge.vrf = vrf;
                    bridge.mac = bridge_id;
                    if let Some(vrf) = vrf{
                        self.state.ifidx_to_vrf.insert(bridge_idx, vrf);
                    }
                    bridge.interfaces.insert(*ifidx);
                    self.state.bridges.insert(bridge_id, bridge);
                }
            }
            self.state.interfaces.insert(*ifidx, interface);
            self.state.ifidx_to_mac.insert(*ifidx, mac);
            self.state.mac_to_ifidx.insert(mac, *ifidx);
            self.global_interface_configuration.lock().unwrap().insert(*ifidx, interface_configuration, 0).unwrap();

        }

        let (routes, oif_gateway) = self.create_routes_for_vrfs().await;
        self.state.routes = routes;

        self.print_route_table();

        for (interface, prefix) in oif_gateway{
            for (ip, _) in &interface.ips{
                if let Some(mac) = self.send_arp_request(prefix, interface.mac, *ip, interface.idx).await{
                    self.state.gateway_mac_table.insert(prefix, mac);
                };
            }

        }

        let mut rx = self.rx.write().await;

        while let Some(command) = rx.recv().await{
            match command{
                NetworkStateCommand::GetBridge { mac, tx } => {
                    let bridge = self.state.bridges.get(&mac);
                    tx.send(bridge.cloned()).unwrap();
                },
                NetworkStateCommand::GetInterface { ifidx, tx } => {
                    let interface = self.state.interfaces.get(&ifidx);
                    tx.send(interface.cloned()).unwrap();
                },
                NetworkStateCommand::GetIfdxFromIp { ip, tx } => {
                    let ifidx = self.state.ip_to_ifidx.get(&ip);
                    tx.send(ifidx.cloned()).unwrap();
                },
                NetworkStateCommand::GetBridgeFromIp { ip, tx } => {
                    let bridge = self.state.ip_to_bridge.get(&ip);
                    tx.send(bridge.cloned()).unwrap();
                },
                NetworkStateCommand::GetRoute { prefix, vrf,  tx } => {
                    let routes: Vec<(u32, u32, [u8; 6])> = self.get_route_from_prefix(prefix, vrf).await;
                    tx.send(routes).unwrap();
                },
                NetworkStateCommand::GetVrfFromIfidx { ifidx, tx } => {
                    let vrf = self.state.ifidx_to_vrf.get(&ifidx);
                    tx.send(vrf.cloned()).unwrap();
                },
                NetworkStateCommand::GetGatewayMacFromPrefix { prefix, tx } => {
                    let mac = self.state.gateway_mac_table.get(&prefix);
                    tx.send(mac.cloned()).unwrap();
                },
                NetworkStateCommand::GetBridgesFromVrf { vrf, tx } => {
                    let bridges: Vec<NetlinkBridge> = self.state.bridges.values().filter(|bridge| bridge.vrf == Some(vrf)).cloned().collect();
                    tx.send(bridges).unwrap();
                },
                NetworkStateCommand::SendArpRequest { prefix, src_mac, src_ip, dst_ifidx, tx } => {
                    let mac = self.send_arp_request(prefix, src_mac, src_ip, dst_ifidx).await;
                    tx.send(mac).unwrap();
                },

            }
        }
        info!("Network state done");
    }
    async fn get_route_from_prefix(&self, prefix: u32, vrf: u32) -> Vec<(u32, u32, [u8;6])>{
        let mut routes = vec![];
        if let Some(route_map) = self.state.routes.get(&vrf){
            for i in (1..=32).rev(){
                let masked_prefix = prefix & (0xFFFFFFFF << (32 - i));
                if let Some(route_list) = route_map.0[i].get(&masked_prefix){
                    routes = route_list.clone();
                }
            }
        } else {
            info!("No routes for vrf: {}", vrf)
        }
        routes
    }
    async fn create_routes_for_vrfs(&self) -> (HashMap<u32, NetlinkRouteList>, Vec<(NetlinkInterface, u32)>){
        let interfaces = self.state.interfaces.clone();
        let mut vrfs = HashSet::new();
        for interface in interfaces.values(){
            if let Some(vrf_) = interface.vrf{
                vrfs.insert(vrf_);
            }
        }
        let mut vrf_routes: HashMap<u32, NetlinkRouteList> = HashMap::new();
        let mut gateway_oif: Vec<(NetlinkInterface, u32)> = Vec::new();
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let mut route_messages = handle.route().get(IpVersion::V4).execute();
        while let Some(route_message) = route_messages.try_next().await.unwrap() {
            let prefix_len = route_message.header.destination_prefix_length;
            if vrfs.contains(&(route_message.header.table as u32)){
                for attr in &route_message.attributes {
                    if let RouteAttribute::Destination(route_address) = attr {
                        if let RouteAddress::Inet(prefix) = route_address {
                            for attr in &route_message.attributes {
                                if let RouteAttribute::Oif(oif) = attr {
                                    if !interfaces.contains_key(oif){
                                        continue;
                                    }
                                    let mut gateway_ip = None;
                                    for attr in &route_message.attributes {
                                        if let RouteAttribute::Gateway(route_address) = attr {
                                            if let RouteAddress::Inet(prefix) = route_address {
                                                let ip = u32::from_be_bytes(prefix.octets());
                                                let ip = Ipv4Addr::from(ip);
                                                gateway_oif.push((interfaces[oif].clone(), u32::from_be_bytes(ip.octets())));
                                                gateway_ip = Some(u32::from_be_bytes(prefix.octets()));
                                            } 
                                        }
                                    }
                                    if let Some(gateway_ip) = gateway_ip{
                                        if let Some(map) = vrf_routes.get_mut(&(route_message.header.table as u32)){
                                            if let Some(list) = map.0[prefix_len as usize].get_mut(&u32::from_be_bytes(prefix.octets())){
                                                list.push((gateway_ip, *oif, interfaces[oif].mac));
                                            } else {
                                                if map.0.get(prefix_len as usize).is_none(){
                                                    map.0[prefix_len as usize] = HashMap::new();
                                                }
                                                map.0[prefix_len as usize].insert(
                                                    u32::from_be_bytes(prefix.octets()),
                                                    vec![(gateway_ip, *oif, interfaces[oif].mac)]
                                                );
                                            }
                                        } else {
                                            let mut route = vec![HashMap::new(); 33];
                                            route[prefix_len as usize] = HashMap::new();
                                            route[prefix_len as usize].insert(
                                                u32::from_be_bytes(prefix.octets()),
                                                vec![(gateway_ip, *oif, interfaces[oif].mac)]
                                            );
                                            vrf_routes.insert(route_message.header.table as u32, NetlinkRouteList(route));
                                        }
                                    }
                                }
                                if let RouteAttribute::MultiPath(route_next_hop_list) = attr{
                                    for route_next_hop in route_next_hop_list{
                                        if !interfaces.contains_key(&route_next_hop.interface_index){
                                            continue;
                                        }
                                        let mut gateway_ip = None;
                                        for attr in &route_next_hop.attributes{
                                            if let RouteAttribute::Gateway(route_address) = attr {
                                                if let RouteAddress::Inet(prefix) = route_address {
                                                    let ip = u32::from_be_bytes(prefix.octets());
                                                    let ip = Ipv4Addr::from(ip);
                                                    gateway_oif.push((interfaces[&route_next_hop.interface_index].clone(), u32::from_be_bytes(ip.octets())));
                                                    gateway_ip = Some(u32::from_be_bytes(prefix.octets()));
                                                } 
                                            }
                                        }
                                        if let Some(gateway_ip) = gateway_ip{
                                            if let Some(map) = vrf_routes.get_mut(&(route_message.header.table as u32)){
                                                if let Some(list) = map.0[prefix_len as usize].get_mut(&u32::from_be_bytes(prefix.octets())){
                                                    list.push((gateway_ip, route_next_hop.interface_index, interfaces[&route_next_hop.interface_index].mac));
                                                } else {
                                                    if map.0.get(prefix_len as usize).is_none(){
                                                        map.0[prefix_len as usize] = HashMap::new();
                                                    }
                                                    map.0[prefix_len as usize].insert(
                                                        u32::from_be_bytes(prefix.octets()),
                                                        vec![(gateway_ip, route_next_hop.interface_index, interfaces[&route_next_hop.interface_index].mac)]
                                                    );
                                                }
                                            } else {
                                                let mut route = vec![HashMap::new(); 33];
                                                route[prefix_len as usize] = HashMap::new();
                                                route[prefix_len as usize].insert(
                                                    u32::from_be_bytes(prefix.octets()),
                                                    vec![(gateway_ip, route_next_hop.interface_index, interfaces[&route_next_hop.interface_index].mac)]
                                                );
                                                vrf_routes.insert(route_message.header.table as u32, NetlinkRouteList(route));
                                            }
                                        } else {
                                            info!("No gateway ip for route_next_hop: {:?}", route_next_hop);
                                        }

                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        (vrf_routes, gateway_oif)
    }
    fn print_route_table(&self){
        for (_, route_map) in &self.state.routes{
            info!("{}", route_map);
        }
    }
    async fn send_arp_request(&self, prefix: u32, src_mac: [u8;6], src_ip: u32, dst_ifidx: u32) -> Option<[u8;6]>{
        let interfaces = datalink::interfaces();
        let interfaces_name_match = |iface: &NetworkInterface| iface.index == dst_ifidx;
        let network_interface = interfaces.into_iter().filter(interfaces_name_match).next().unwrap();
    
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(src_mac.into());
        ethernet_packet.set_ethertype(EtherTypes::Arp);
    
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(src_mac.into());
        arp_packet.set_sender_proto_addr(Ipv4Addr::from(src_ip));
        arp_packet.set_target_hw_addr(MacAddr::broadcast());
        arp_packet.set_target_proto_addr(Ipv4Addr::from(prefix));
        ethernet_packet.set_payload(arp_packet.packet_mut());
    
        let mut configuration = Config::default();
        configuration.read_timeout = Some(std::time::Duration::from_millis(10));
        let (mut tx, mut rx) = match datalink::channel(&network_interface, configuration) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
    

        tx.send_to(&ethernet_packet.to_immutable().packet(), Some(network_interface.clone()));
        loop {
            info!("Waiting for arp response");
            let buf = match rx.next(){
                Ok(buf) => buf,
                Err(_e) => {
                    return None;
                }
            };
            info!("Got arp response");
            let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
            if arp.get_sender_proto_addr() == Ipv4Addr::from(prefix)
                && arp.get_target_hw_addr() == Into::<MacAddr>::into(src_mac)
            {
                return Some(arp.get_sender_hw_addr().into());
            }
        }
    }
}

#[derive(Clone)]
pub struct NetworkStateClient{
    tx: tokio::sync::mpsc::Sender<NetworkStateCommand>,
}

impl NetworkStateClient{
    fn new(tx: tokio::sync::mpsc::Sender<NetworkStateCommand>) -> Self{
        Self{
            tx,
        }
    }
    pub async fn get_bridge(&self, mac: [u8;6]) -> Option<NetlinkBridge>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetBridge{mac, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_interface(&self, ifidx: u32) -> Option<NetlinkInterface>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetInterface{ifidx, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_ifdx_from_ip(&self, ip: u32) -> Option<u32>{
        let local_tx = self.tx.clone();
        info!("Getting ifidx from ip: {}", ip);
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetIfdxFromIp{ip, tx}).await.unwrap();
        info!("Sent request");
        let res = rx.await;
        if let Ok(res) = res{
            info!("Got response: {:?}", res);
            res
        } else {
            info!("Error getting response");
            None
        }
    }
    pub async fn get_bridge_from_ip(&self, ip: u32) -> Option<[u8;6]>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetBridgeFromIp{ip, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_routes(&self, prefix: u32, vrf: u32) -> Vec<(u32, u32, [u8;6])>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetRoute{prefix, vrf, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_vrf_from_ifidx(&self, ifidx: u32) -> Option<u32>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetVrfFromIfidx{ifidx, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_gateway_mac_from_prefix(&self, prefix: u32) -> Option<[u8;6]>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetGatewayMacFromPrefix{prefix, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn get_bridges_from_vrf(&self, vrf: u32) -> Vec<NetlinkBridge>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::GetBridgesFromVrf{vrf, tx}).await.unwrap();
        rx.await.unwrap()
    }
    pub async fn send_arp_request(&self, prefix: u32, src_mac: [u8;6], src_ip: u32, dst_ifidx: u32) -> Option<[u8;6]>{
        let local_tx = self.tx.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        local_tx.send(NetworkStateCommand::SendArpRequest{prefix, src_mac, src_ip, dst_ifidx, tx}).await.unwrap();
        rx.await.unwrap()
    }
}

pub enum NetworkStateCommand{
    GetBridge{
        mac: [u8;6],
        tx: tokio::sync::oneshot::Sender<Option<NetlinkBridge>>,
    },
    GetInterface{
        ifidx: u32,
        tx: tokio::sync::oneshot::Sender<Option<NetlinkInterface>>,
    },
    GetRoute{
        prefix: u32,
        vrf: u32,
        tx: tokio::sync::oneshot::Sender<Vec<(u32, u32, [u8; 6])>>,
    },
    GetIfdxFromIp{
        ip: u32,
        tx: tokio::sync::oneshot::Sender<Option<u32>>,
    },
    GetBridgeFromIp{
        ip: u32,
        tx: tokio::sync::oneshot::Sender<Option<[u8;6]>>,
    },
    GetVrfFromIfidx{
        ifidx: u32,
        tx: tokio::sync::oneshot::Sender<Option<u32>>,
    },
    GetGatewayMacFromPrefix{
        prefix: u32,
        tx: tokio::sync::oneshot::Sender<Option<[u8;6]>>,
    },
    GetBridgesFromVrf{
        vrf: u32,
        tx: tokio::sync::oneshot::Sender<Vec<NetlinkBridge>>,
    },
    SendArpRequest{
        prefix: u32,
        src_mac: [u8;6],
        src_ip: u32,
        dst_ifidx: u32,
        tx: tokio::sync::oneshot::Sender<Option<[u8;6]>>,
    },
}

async fn get_bridge_id_from_ifidx(idx: u32)  -> Option<[u8;6]>{
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

async fn get_mac_address_from_ifidx(idx: u32) -> [u8;6]{
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let link_msg = handle.link().get().match_index(idx).execute().try_next().await.unwrap().unwrap();
    let mut mac_res = None;
    for attr in &link_msg.attributes {
        if let LinkAttribute::Address(mac_array) = attr {
            mac_res = Some(mac_array.to_vec().try_into().unwrap());
        }
    }
    mac_res.unwrap()
}

async fn get_vrf_from_ifidx(idx: u32) -> Option<u32>{
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let link_msg = handle.link().get().match_index(idx).execute().try_next().await.unwrap().unwrap();
    let mut vrf_res = None;
    for attr in &link_msg.attributes {
        if let LinkAttribute::LinkInfo(link_info_list) = &attr {
            for link_info in link_info_list {
                if let LinkInfo::PortKind(port_kind) = link_info {
                    if let InfoPortKind::Other(other) = port_kind {
                        if other == "vrf" {
                            for link_info in link_info_list{
                                if let LinkInfo::PortData(port_data) = link_info{
                                    if let InfoPortData::Other(other) = port_data{
                                        let data: [u8;4] = other[4..].try_into().unwrap();
                                        let vrf = u32::from_le_bytes(data);
                                        vrf_res = Some(vrf);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    vrf_res
}

async fn get_ifidx_from_mac(mac: [u8;6]) -> Option<u32>{
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut ifidx_res = None;
    let mut links = handle.link().get().execute();
    while let Some(link_message) = links.try_next().await.unwrap() {
        for attr in &link_message.attributes {
            if let LinkAttribute::Address(mac_array) = attr {
                let mac_: [u8;6] = mac_array.to_vec().try_into().unwrap();
                if mac_ == mac {
                    ifidx_res = Some(link_message.header.index);
                }

            }
        }
    }
    ifidx_res
}

async fn get_ip_addresses_from_ifidx(idx: u32) -> Vec<(u32, u8)>{
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut ips = Vec::new();
    let mut addresses = handle.address().get().set_link_index_filter(idx).execute();
    while let Some(address_message) = addresses.try_next().await.unwrap() {
        if address_message.header.family == AddressFamily::Inet  {
            let prefix_len = address_message.header.prefix_len;
            for attr in address_message.attributes {
                if let address::AddressAttribute::Local(local) = attr {
                    match local {
                        IpAddr::V4(ip) => {
                            ips.push((u32::from_be_bytes(ip.octets()), prefix_len));
                        },
                        _ => {}
                    }
                }
            }
            
        }
    }
    ips
}



/*
route_msg: RouteMessage { header: RouteHeader { address_family: Inet, destination_prefix_length: 24, source_prefix_length: 0, tos: 0, table: 100, protocol: Boot, scope: Universe, kind: Unicast, flags: [] }, attributes: [Table(100), Destination(Inet(192.168.1.0)), MultiPath([RouteNextHop { flags: [], hops: 0, interface_index: 60, attributes: [Gateway(Inet(1.1.1.2))] }, RouteNextHop { flags: [], hops: 0, interface_index: 62, attributes: [Gateway(Inet(2.2.2.2))] }])] }
route_msg: RouteMessage { header: RouteHeader { address_family: Inet, destination_prefix_length: 24, source_prefix_length: 0, tos: 0, table: 100, protocol: Boot, scope: Universe, kind: Unicast, flags: [] }, attributes: [Table(100), Destination(Inet(192.168.1.0)), MultiPath([RouteNextHop { flags: [], hops: 0, interface_index: 60, attributes: [Gateway(Inet(1.1.1.2))] }, RouteNextHop { flags: [], hops: 0, interface_index: 62, attributes: [Gateway(Inet(2.2.2.2))] }])] }
route_msg: RouteMessage { header: RouteHeader { address_family: Inet, destination_prefix_length: 24, source_prefix_length: 0, tos: 0, table: 100, protocol: Boot, scope: Universe, kind: Unicast, flags: [] }, attributes: [Table(100), Destination(Inet(192.168.5.0)), Gateway(Inet(1.1.1.2)), Oif(60)] }

*/