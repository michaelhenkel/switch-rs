use std::{collections::HashMap, sync::Arc};
use aya::maps::{HashMap as BpfHashMap, MapData};
use log::info;
use switch_rs_common::{FlowKey, FlowNextHop};
use tokio::sync::{mpsc::Receiver, RwLock};

pub struct FlowManager{
    rx: Arc<RwLock<Receiver<FlowCommand>>>,
    client: FlowManagerClient,
}

impl FlowManager{
    pub fn new() -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let client = FlowManagerClient::new(tx.clone());
        FlowManager{
            rx: Arc::new(RwLock::new(rx)),
            client,
        }
    }
    pub async fn run(&mut self, mut global_flow_table: BpfHashMap<MapData, FlowKey, FlowNextHop>){
        let mut jh_list = Vec::new();
        let mut monitor_interval = tokio::time::interval(tokio::time::Duration::from_micros(500));
        let mut local_flow_table: HashMap<FlowKey, Vec<FlowNextHop>> = HashMap::new();
        let rx = self.rx.clone();
        let jh = tokio::spawn(async move {
            let mut rx = rx.write().await;
            loop{
                tokio::select! {
                    cmd = rx.recv() => {
                        if let Some(cmd) = cmd{
                            match cmd{
                                FlowCommand::AddFlow { fwd_rev_flow } => {
                                    let fwd_flow = fwd_rev_flow.fwd;
                                    let rev_flow = fwd_rev_flow.rev;
                                    let fwd_key = fwd_flow.key;
                                    let rev_key = rev_flow.key;
                                    let mut fwd_next_hops = fwd_flow.next_hops;
                                    let rev_next_hops = rev_flow.next_hops;
                                    if fwd_next_hops.is_empty() || rev_next_hops.is_empty(){
                                        continue;
                                    }
                                    for nh in &mut fwd_next_hops{
                                        nh.active_next_hop = 0;
                                    }
                                    local_flow_table.insert(fwd_key, fwd_next_hops.clone());
                                    local_flow_table.insert(rev_key, rev_next_hops.clone());
                
                                    if let Err(e) = global_flow_table.insert(fwd_key, fwd_next_hops[0],0){
                                        log::error!("Failed to insert flow into global flow table: {}", e);
                                    }
                                    if let Err(e) = global_flow_table.insert(rev_key, rev_next_hops[0],0){
                                        log::error!("Failed to insert flow into global flow table: {}", e);
                                    }
                                },
                                FlowCommand::GetIfidxQueue { flow_key, tx } => {
                                    if let Some(existing_flow_list) = local_flow_table.get(&flow_key){
                                        if existing_flow_list.len() > 0{
                                            let active_flow = global_flow_table.get(&flow_key, 0).unwrap();
                                            let active_next_hop = active_flow.active_next_hop;
                                            let next_active_next_hop_index = (active_next_hop + 1) % existing_flow_list.len() as u32;
                                            let mut next_active_next_hop = existing_flow_list[next_active_next_hop_index as usize];
                                            next_active_next_hop.active_next_hop = next_active_next_hop_index;
                                            next_active_next_hop.packet_count = 0;
                                            let _ = global_flow_table.insert(&flow_key, next_active_next_hop, 0);
                                        } else {
                                            let _ = tx.send(Some((existing_flow_list[0].ifidx, existing_flow_list[0].queue_id)));
                                        }
                                    } else {
                                        let _ = tx.send(None);
                                    }
                                },
                            }
                        }
                    },
                    _ = monitor_interval.tick() => {
                        for (flow_key, flow_list) in &local_flow_table{
                            if flow_list.len() > 1{
                                let active_flow = global_flow_table.get(flow_key, 0).unwrap();
                                if active_flow.packet_count > active_flow.max_packets{
                                    let active_next_hop = active_flow.active_next_hop;
                                    let next_active_next_hop_index = (active_next_hop + 1) % flow_list.len() as u32;
                                    let mut next_active_next_hop = flow_list[next_active_next_hop_index as usize];
                                    next_active_next_hop.active_next_hop = next_active_next_hop_index;
                                    next_active_next_hop.packet_count = 0;
                                    let _ = global_flow_table.insert(flow_key, next_active_next_hop, 0);
                                    info!("Switched flow for flow_key: {:?}", flow_key);
                                }
                            }
                        }
                    }
                
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

#[derive(Clone)]
pub struct FlowManagerClient{
    tx: tokio::sync::mpsc::Sender<FlowCommand>,
}

impl FlowManagerClient{
    pub fn new(tx: tokio::sync::mpsc::Sender<FlowCommand>) -> Self{
        FlowManagerClient{tx}
    }
    pub async fn add_flow(&self, fwd_rev_flow: FwdRevFlow) -> anyhow::Result<()>{
        self.tx.send(FlowCommand::AddFlow{fwd_rev_flow}).await.
            map_err(|e| anyhow::anyhow!("Failed to send add flow command: {}", e))
    }
    pub async fn get_ifidx_queue(&self, flow_key: FlowKey) -> anyhow::Result<Option<(u32, u32)>>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(FlowCommand::GetIfidxQueue{flow_key, tx});
        rx.await.map_err(|e| anyhow::anyhow!("Failed to get ifidx queue: {}", e))
    }
}

pub enum FlowCommand{
    AddFlow{
        fwd_rev_flow: FwdRevFlow,
    },
    GetIfidxQueue{
        flow_key: FlowKey,
        tx: tokio::sync::oneshot::Sender<Option<(u32, u32)>>,
    },
}

#[derive(Default)]
pub struct Flow{
    pub key: FlowKey,
    pub next_hops: Vec<FlowNextHop>,
}

#[derive(Default)]
pub struct FwdRevFlow{
    pub fwd: Flow,
    pub rev: Flow,
}