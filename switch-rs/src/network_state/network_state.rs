use std::{collections::{BTreeMap, HashMap, HashSet}, net::IpAddr, sync::Arc};

use futures::TryStreamExt;
use log::info;
use netlink_packet_route::{address, link::{InfoBridgePort, InfoPortData, LinkAttribute, LinkInfo}, AddressFamily};
use rtnetlink::new_connection;
use tokio::{runtime::Builder, sync::RwLock};

use crate::af_xdp::interface::{self, interface::Interface};


#[derive(Debug, Default, Clone)]
struct State{
    bridges: HashMap<[u8;6],NetlinkBridge>,
    ip_to_bridge: HashMap<u32,[u8;6]>,
    interfaces: HashMap<u32,NetlinkInterface>,
    mac_to_ifidx: HashMap<[u8;6],u32>,
    ifidx_to_mac: HashMap<u32,[u8;6]>,
    ip_to_ifidx: HashMap<u32,u32>,
    routes: BTreeMap<u8,HashMap<u32,Vec<u32>>>,
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkBridge{
    ips: Vec<u32>,
    idx: u32,
    interfaces: HashSet<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkInterface{
    mac: [u8;6],
    idx: u32,
    ips: Vec<u32>,
    bridge_id: Option<[u8;6]>,
}

#[derive(Debug, Default, Clone)]
pub struct NetlinkRoute{
    prefix: u32,
    next_hops: Vec<u32>,
}

pub struct NetworkState{
    rx: Arc<RwLock<tokio::sync::mpsc::Receiver<NetworkStateCommand>>>,
    client: NetworkStateClient,
    interface_list: HashMap<u32, Interface>,
}

impl NetworkState{
    pub fn new(interface_list: HashMap<u32, Interface>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let client = NetworkStateClient::new(tx);
        Self{
            rx: Arc::new(RwLock::new(rx)),
            client,
            interface_list,
        }
    }
    pub fn client(&self) -> NetworkStateClient{
        self.client.clone()
    }
    pub async fn run(&mut self){
        let mut state = State::default();
        for (ifidx, _) in &self.interface_list{
            let addresses = get_ip_addresses_from_ifidx(*ifidx).await;
            let mac = get_mac_address_from_ifidx(*ifidx).await;
            let mut interface = NetlinkInterface::default();
            for ip in &addresses{
                state.ip_to_ifidx.insert(*ip, *ifidx);
            }
            interface.ips = addresses;
            interface.idx = *ifidx;
            interface.mac = mac;
            let bridge_id = get_bridge_id_from_ifidx(*ifidx).await;
            if let Some(bridge_id) = bridge_id{
                interface.bridge_id = Some(bridge_id);
                if let Some(bridge) = state.bridges.get_mut(&bridge_id){
                    bridge.interfaces.insert(*ifidx);
                } else {
                    let bridge_idx = get_ifidx_from_mac(bridge_id).await.unwrap();
                    let addresses = get_ip_addresses_from_ifidx(bridge_idx).await;
                    for address in &addresses{
                        state.ip_to_bridge.insert(*address, bridge_id);
                    }
                    let mut bridge = NetlinkBridge::default();
                    bridge.ips = addresses;
                    bridge.idx = bridge_idx;
                    bridge.interfaces.insert(*ifidx);
                    state.bridges.insert(bridge_id, bridge);

                }
            }
            state.interfaces.insert(*ifidx, interface);
            state.ifidx_to_mac.insert(*ifidx, mac);
            state.mac_to_ifidx.insert(mac, *ifidx);

        }
        info!("State: {:#?}", state);
        let mut rx = self.rx.write().await;

        while let Some(command) = rx.recv().await{
            info!("Got command");
            match command{
                NetworkStateCommand::GetBridge { mac, tx } => {
                    let bridge = state.bridges.get(&mac);
                    tx.send(bridge.cloned()).unwrap();
                },
                NetworkStateCommand::GetInterface { ifidx, tx } => {
                    let interface = state.interfaces.get(&ifidx);
                    tx.send(interface.cloned()).unwrap();
                },
                NetworkStateCommand::GetIfdxFromIp { ip, tx } => {
                    info!("Getting ifidx from ip: {}", ip);
                    let ifidx = state.ip_to_ifidx.get(&ip);
                    info!("Got ifidx: {:?}", ifidx);
                    tx.send(ifidx.cloned()).unwrap();
                },
                NetworkStateCommand::GetBridgeFromIp { ip, tx } => {
                    let bridge = state.ip_to_bridge.get(&ip);
                    tx.send(bridge.cloned()).unwrap();
                },
                NetworkStateCommand::GetRoute { prefix, tx } => {
                    
                },
            }
        }
        info!("Network state done");
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
        tx: tokio::sync::oneshot::Sender<Option<NetlinkRoute>>,
    },
    GetIfdxFromIp{
        ip: u32,
        tx: tokio::sync::oneshot::Sender<Option<u32>>,
    },
    GetBridgeFromIp{
        ip: u32,
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

async fn get_ip_addresses_from_ifidx(idx: u32) -> Vec<u32>{
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut ips = Vec::new();
    let mut addresses = handle.address().get().set_link_index_filter(idx).execute();
    while let Some(address_message) = addresses.try_next().await.unwrap() {
        if address_message.header.family == AddressFamily::Inet  {
            for attr in address_message.attributes {
                if let address::AddressAttribute::Local(local) = attr {
                    match local {
                        IpAddr::V4(ip) => {
                            ips.push(u32::from_be_bytes(ip.octets()));
                        },
                        _ => {}
                    }
                }
            }
            
        }
    }
    ips
}