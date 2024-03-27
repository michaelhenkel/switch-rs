use std::{collections::HashMap, sync::{atomic::AtomicU64, Arc, Mutex}};
use aya::maps::{HashMap as BpfHashMap, MapData};
use switch_rs_common::{FlowKey, FlowNextHop, InterfaceConfiguration, InterfaceStats};
use tokio::{sync::{mpsc::Receiver, RwLock}, time::Instant};
use crate::network_state::network_state::NetworkStateClient;

const FLOWLET_SIZE: u32 = 10;

pub struct FlowManager{
    rx: Arc<RwLock<Receiver<FlowCommand>>>,
    client: FlowManagerClient,
    network_state_client: NetworkStateClient,
}

impl FlowManager{
    pub fn new(network_state_client: NetworkStateClient) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let client = FlowManagerClient::new(tx.clone());
        FlowManager{
            rx: Arc::new(RwLock::new(rx)),
            client,
            network_state_client,
        }
    }
    pub async fn run(
        &mut self,
        mut global_flow_table: BpfHashMap<MapData, FlowKey, FlowNextHop>,
        mut interface_stats: BpfHashMap<MapData, u32, InterfaceStats>,
        interface_config: Arc<RwLock<BpfHashMap<MapData, u32, InterfaceConfiguration>>>,
        mut ecn_marker_table: BpfHashMap<MapData, FlowKey, u8>,
    ){
        let mut jh_list = Vec::new();
        let mut pause_on = false;
        let mut monitor_interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        let mut local_flow_table: HashMap<FlowKey, LocalNextHop> = HashMap::new();
        let mut flow_timeout = 10;
        let mut max_packets = 1000;
        let mut flowlet_size = FLOWLET_SIZE;
        let network_state_client = self.network_state_client.clone();
        let rx = self.rx.clone();
        let jh = tokio::spawn(async move {
            let mut rx = rx.write().await;
            loop{
                tokio::select! {
                    cmd = rx.recv() => {
                        if let Some(cmd) = cmd{
                            match cmd{
                                FlowCommand::AddFlow { flow } => {
                                    let flow_key = flow.key;
                                    let mut flow_next_hops = flow.next_hops;
                                    if flow_next_hops.is_empty(){
                                        continue;
                                    }
                                    let mut nh_ranked_list = Vec::new();
                                    for next_hop in &flow_next_hops{
                                        let iface_stats = interface_stats.get(&next_hop.oif_idx, 0).unwrap();
                                        nh_ranked_list.push((iface_stats.flows, next_hop.clone()));
                                    }
                                    nh_ranked_list.sort_by(|a,b|a.0.cmp(&b.0));

                                    flow_next_hops = nh_ranked_list.into_iter().map(|(_, v)| v).collect();

                                    for nh in &mut flow_next_hops{
                                        nh.active_next_hop = 0;
                                    }
                                    let now = tokio::time::Instant::now();
                                    local_flow_table.insert(flow_key, LocalNextHop{next_hop_list: flow_next_hops.clone(), last_updated: now, packet_count: 0});

                                    if let Err(e) = global_flow_table.insert(flow_key, flow_next_hops[0],0){
                                        log::error!("Failed to insert flow into global flow table: {}", e);
                                    }

                                    if let Ok(mut stats) = interface_stats.get(&flow_next_hops[0].oif_idx, 0){
                                        stats.flows += 1;
                                        interface_stats.insert(&flow_next_hops[0].oif_idx, stats, 0).unwrap();
                                    }
                                },
                                FlowCommand::GetIfidxQueue { flow_key, tx } => {
                                    let active_flow = global_flow_table.get(&flow_key, 0).ok();
                                    let res = if let Some(active_flow) = active_flow{
                                        Some((active_flow.oif_idx, active_flow.queue_id))
                                    } else {
                                        None
                                    };
                                    tx.send(res).unwrap();
                                },
                                FlowCommand::GetStats { ifidx, tx } => {
                                    let stats = interface_stats.get(&ifidx, 0).unwrap();
                                    let _ = tx.send(stats);
                                },
                                FlowCommand::ListStats { tx } => {
                                    let mut stats_map = HashMap::new();
                                    for res in interface_stats.iter(){
                                        if let Ok((ifidx, stats)) = res{
                                            stats_map.insert(ifidx, stats.clone());
                                        }
                                    }
                                    let _ = tx.send(stats_map);
                                },
                                FlowCommand::UpdateInterfaceConfiguration { ifidx, interface_configuration } => {
                                    //let _ = interface_config.lock().unwrap().insert(&ifidx, interface_configuration, 0);
                                },
                                FlowCommand::ListFlows { tx } => {
                                    let mut flow_map = HashMap::new();
                                    for res in global_flow_table.iter(){
                                        if let Ok((flow_key, flow_next_hop)) = res{
                                            if let Some(local_next_hop) = local_flow_table.get(&flow_key){
                                                flow_map.insert(flow_key.clone(), (flow_next_hop.clone(), local_next_hop.last_updated));
                                            }
                                        }
                                    }
                                    let _ = tx.send(flow_map);
                                },
                                FlowCommand::IncrStatsPacketCount { ifidx } => {
                                    if let Ok(mut stats) = interface_stats.get(&ifidx, 0){
                                        stats.tx_packets += 1;
                                        interface_stats.insert(&ifidx, stats, 0).unwrap();
                                    }
                                },
                                FlowCommand::IncrFlowPacketCount { flow_key } => {
                                    if let Ok(mut flow) = global_flow_table.get(&flow_key, 0){
                                        flow.packet_count += 1;
                                        let _ = global_flow_table.insert(flow_key, flow, 0);
                                    }
                                },
                                FlowCommand::SetMaxPackets { max_packets: mp } => {
                                    max_packets = mp;
                                },
                                FlowCommand::SetFlowTimeout { flow_timeout: ft } => {
                                    flow_timeout = ft;
                                },
                                FlowCommand::ShowFlowTimeout { tx } => {
                                    tx.send(flow_timeout).map_err(|e| log::error!("Failed to show flow timeout: {}", e)).unwrap();
                                },
                                FlowCommand::ShowMaxPackets { tx } => {
                                    tx.send(max_packets).map_err(|e| log::error!("Failed to show max packets: {}", e)).unwrap();
                                },
                                FlowCommand::TogglePause { on_off } => {
                                    pause_on = on_off;
                                },
                                FlowCommand::ShowPause { tx } => {
                                    tx.send(pause_on).map_err(|e| log::error!("Failed to show pause: {}", e)).unwrap();
                                },
                                FlowCommand::SetFlowletSize { flowlet_size: fs } => {
                                    flowlet_size = fs;
                                    let mut res_map = HashMap::new();
                                    for res in interface_config.write().await.iter(){
                                        if let Ok((ifidx, mut interface_configuration)) = res {
                                            interface_configuration.flowlet_size = fs;
                                            res_map.insert(ifidx.clone(), interface_configuration.clone());
                                        }
                                    }
                                    for (ifidx, interface_configuration) in res_map{
                                        interface_config.write().await.insert(&ifidx, interface_configuration, 0).unwrap();
                                    }
                                },
                                FlowCommand::ShowFlowletSize { tx } => {
                                    tx.send(flowlet_size).map_err(|e| log::error!("Failed to show flowlet size: {}", e)).unwrap();
                                },
                            }
                        }
                    },
                    _ = monitor_interval.tick() => {
                        let mut inactive_flows = Vec::new();
                        for (flow_key, local_next_hop) in &mut local_flow_table{
                            let flow_list = &local_next_hop.next_hop_list;
                            if let Ok(active_flow) = global_flow_table.get(flow_key, 0){
                                let now = tokio::time::Instant::now();
                                if now.duration_since(local_next_hop.last_updated).as_secs() >= flow_timeout && active_flow.packet_count == local_next_hop.packet_count{
                                    inactive_flows.push((flow_key.clone(), active_flow.oif_idx));
                                    continue;
                                }
                                if active_flow.packet_count > local_next_hop.packet_count{
                                    local_next_hop.last_updated = now;
                                }
                                let packet_rate = active_flow.packet_count - local_next_hop.packet_count;
                                let dur = now.duration_since(local_next_hop.last_updated).as_millis() as u64;
                                if packet_rate > 0 && dur > 0{
                                    let packet_rate = packet_rate / dur;
                                    if let Ok(mut stats) = interface_stats.get(&active_flow.oif_idx, 0){
                                        stats.rate = packet_rate;
                                        interface_stats.insert(&active_flow.oif_idx, stats, 0).unwrap();
                                    }
                                }
                                local_next_hop.packet_count = active_flow.packet_count;
                                if flow_list.len() > 1{


                                    if active_flow.packet_count > flowlet_size as u64 && flowlet_size > 0{
                                        let active_next_hop = active_flow.active_next_hop;
                                        let next_active_next_hop_index = (active_next_hop + 1) % flow_list.len() as u32;
                                        let mut next_active_next_hop = flow_list[next_active_next_hop_index as usize];
                                        next_active_next_hop.active_next_hop = next_active_next_hop_index;
                                        next_active_next_hop.packet_count = 0;
                                        let _ = global_flow_table.insert(flow_key, next_active_next_hop, 0);
                                        if let Ok(mut stats) = interface_stats.get(&active_flow.oif_idx, 0){
                                            if stats.flows > 0{
                                                stats.flows -= 1;
                                                interface_stats.insert(&active_flow.oif_idx, stats, 0).unwrap();
                                            }
                                        }
                                        if let Ok(mut stats) = interface_stats.get(&next_active_next_hop.oif_idx, 0){
                                            stats.flows += 1;
                                            interface_stats.insert(&next_active_next_hop.oif_idx, stats, 0).unwrap();
                                        }
                                    }
                                }
                            }
                        }
                        for (flow_key, ifidx) in inactive_flows{
                            local_flow_table.remove(&flow_key);
                            let _ = global_flow_table.remove(&flow_key);
                            if let Ok(mut stats) = interface_stats.get(&ifidx, 0){
                                if stats.flows > 0{
                                    stats.flows -= 1;
                                    interface_stats.insert(&ifidx, stats, 0).unwrap();
                                }
                            }
                        }
                        if pause_on{
                            let mut reset_stats = HashMap::new();
                            for res in interface_stats.iter(){
                                if let Ok((interface, mut stats)) = res{
                                    if let Ok(interface_configuration) = interface_config.read().await.get(&interface, 0){
                                        if interface_configuration.l2 == 1{
                                            if stats.flowlet_packets > 0 && stats.flowlet_packets >= max_packets as u32{
                                                network_state_client.send_pause_frame(interface_configuration.mac, interface).await;
                                                stats.flowlet_packets = 0;
                                                stats.pause_sent += 1;
                                                reset_stats.insert(interface, stats);
                                                
                                            }
                                        }
                                    }
                                }
                            }
                            for (intf, stats) in reset_stats{
                                interface_stats.insert(&intf, stats, 0).unwrap();
                            }
                        }

                    },
                }
            }
        });

        jh_list.push(jh);
        futures::future::join_all(jh_list).await;

    }

    pub fn client(&self) -> FlowManagerClient{
        self.client.clone()
    }

}

struct LocalNextHop{
    next_hop_list: Vec<FlowNextHop>,
    last_updated: Instant,
    packet_count: u64,
}

#[derive(Clone)]
pub struct FlowManagerClient{
    tx: tokio::sync::mpsc::Sender<FlowCommand>,
}

impl FlowManagerClient{
    pub fn new(tx: tokio::sync::mpsc::Sender<FlowCommand>) -> Self{
        FlowManagerClient{tx}
    }
    pub async fn add_flow(&self, flow: Flow) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::AddFlow{flow}).await.
            map_err(|e| anyhow::anyhow!("Failed to send add flow command: {}", e))
    }
    pub async fn get_ifidx_queue(&self, flow_key: FlowKey) -> anyhow::Result<Option<(u32, u32)>>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(FlowCommand::GetIfidxQueue{flow_key, tx}).await;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to get ifidx queue: {}", e))
    }
    pub async fn get_stats(&self, ifidx: u32) -> anyhow::Result<InterfaceStats>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(FlowCommand::GetStats{ifidx, tx}).await;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to get stats: {}", e))
    }
    pub async fn list_stats(&self) -> anyhow::Result<HashMap<u32, InterfaceStats>>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(FlowCommand::ListStats{tx}).await;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to list stats: {}", e))
    }
    pub async fn update_interface_configuration(&self, ifidx: u32, interface_configuration: InterfaceConfiguration) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::UpdateInterfaceConfiguration{ifidx, interface_configuration}).await.
            map_err(|e| anyhow::anyhow!("Failed to send update interface configuration command: {}", e))
    }
    pub async fn list_flows(&self) -> anyhow::Result<HashMap<FlowKey, (FlowNextHop, tokio::time::Instant)>>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(FlowCommand::ListFlows{tx}).await;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to list flows: {}", e))
    }
    pub async fn incr_stats_packet_count(&self, ifidx: u32) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::IncrStatsPacketCount{ifidx}).await.
            map_err(|e| anyhow::anyhow!("Failed to send increment stats packet count command: {}", e))
    }
    pub async fn incr_flow_packet_count(&self, flow_key: FlowKey) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::IncrFlowPacketCount{flow_key}).await.
            map_err(|e| anyhow::anyhow!("Failed to send increment flow packet count command: {}", e))
    }
    pub async fn set_max_packets(&self, max_packets: u64) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::SetMaxPackets{max_packets}).await.
            map_err(|e| anyhow::anyhow!("Failed to send set max packets command: {}", e))
    }
    pub async fn set_flow_timeout(&self, flow_timeout: u64) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::SetFlowTimeout{flow_timeout}).await.
            map_err(|e| anyhow::anyhow!("Failed to send set flow timeout command: {}", e))
    }
    pub async fn show_flow_timeout(&self) -> anyhow::Result<u64>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(FlowCommand::ShowFlowTimeout{tx}).await.
            map_err(|e| anyhow::anyhow!("Failed to send show flow timeout command: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to show flow timeout: {}", e))
    }
    pub async fn show_max_packets(&self) -> anyhow::Result<u64>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(FlowCommand::ShowMaxPackets{tx}).await.
            map_err(|e| anyhow::anyhow!("Failed to send show max packets command: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to show max packets: {}", e))
    }
    pub async fn toggle_pause(&self, on_off: bool) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::TogglePause{on_off}).await.
            map_err(|e| anyhow::anyhow!("Failed to send toggle pause command: {}", e))
    }
    pub async fn show_pause(&self) -> anyhow::Result<bool>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(FlowCommand::ShowPause{tx}).await.
            map_err(|e| anyhow::anyhow!("Failed to send show pause command: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to show pause: {}", e))
    }
    pub async fn set_flowlet_size(&self, flowlet_size: u32) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::SetFlowletSize{flowlet_size}).await.
            map_err(|e| anyhow::anyhow!("Failed to send set flowlet size command: {}", e))
    }
    pub async fn show_flowlet_size(&self) -> anyhow::Result<u32>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(FlowCommand::ShowFlowletSize{tx}).await.
            map_err(|e| anyhow::anyhow!("Failed to send show flowlet size command: {}", e))?;
        rx.await.map_err(|e| anyhow::anyhow!("Failed to show flowlet size: {}", e))
    }
}

pub enum FlowCommand{
    AddFlow{
        flow: Flow,
    },
    GetIfidxQueue{
        flow_key: FlowKey,
        tx: tokio::sync::oneshot::Sender<Option<(u32, u32)>>,
    },
    GetStats{
        ifidx: u32,
        tx: tokio::sync::oneshot::Sender<InterfaceStats>,
    },
    ListStats{
        tx: tokio::sync::oneshot::Sender<HashMap<u32, InterfaceStats>>,
    },
    UpdateInterfaceConfiguration{
        ifidx: u32,
        interface_configuration: InterfaceConfiguration,
    },
    ListFlows{
        tx: tokio::sync::oneshot::Sender<HashMap<FlowKey, (FlowNextHop, tokio::time::Instant)>>,
    },
    IncrStatsPacketCount{
        ifidx: u32,
    },
    IncrFlowPacketCount{
        flow_key: FlowKey,
    },
    SetMaxPackets{
        max_packets: u64,
    },
    SetFlowTimeout{
        flow_timeout: u64,
    },
    SetFlowletSize{
        flowlet_size: u32,
    },
    ShowFlowletSize{
        tx: tokio::sync::oneshot::Sender<u32>,
    },
    ShowFlowTimeout{
        tx: tokio::sync::oneshot::Sender<u64>,
    },
    ShowMaxPackets{
        tx: tokio::sync::oneshot::Sender<u64>,
    },
    TogglePause{
        on_off: bool,
    },
    ShowPause{
        tx: tokio::sync::oneshot::Sender<bool>,
    }
}

#[derive(Default)]
pub struct Flow{
    pub key: FlowKey,
    pub next_hops: Vec<FlowNextHop>,
}