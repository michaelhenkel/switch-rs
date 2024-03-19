use std::{collections::HashMap, f64::consts::E, fmt::Display, net::Ipv4Addr, sync::{Arc, Mutex}};
use aya::maps::{HashMap as BpfHashMap, MapData};
use log::{error,info};
use switch_rs_common::{FlowKey, FlowNextHop};
use tokio::sync::{mpsc::Receiver, RwLock};

pub struct FlowManager{
    rx: Arc<RwLock<Receiver<FlowCommand>>>,
    client: FlowManagerClient,
    global_flow_table: Arc<Mutex<BpfHashMap<MapData, FlowKey, FlowNextHop>>>,
    local_flow_table: HashMap<FlowKey, Vec<FlowNextHop>>,
}

impl FlowManager{
    pub fn new(global_flow_table: Arc<Mutex<BpfHashMap<MapData, FlowKey, FlowNextHop>>>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(1000000);
        let client = FlowManagerClient::new(tx.clone());
        FlowManager{
            rx: Arc::new(RwLock::new(rx)),
            client,
            global_flow_table,
            local_flow_table: HashMap::new(),
        }
    }
    pub async fn run(&mut self){
        info!("FlowManager started");
        let mut rx = self.rx.write().await;
        while let Some(cmd) = rx.recv().await{
            match cmd{
                FlowCommand::AddFlow { fwd_rev_flow } => {
                    let fwd_flow = fwd_rev_flow.fwd;
                    let rev_flow = fwd_rev_flow.rev;
                    let fwd_key = fwd_flow.key;
                    let rev_key = rev_flow.key;
                    let mut fwd_next_hops = fwd_flow.next_hops;
                    if fwd_next_hops.is_empty(){
                        info!("No next hops for flow");
                        continue;
                    }
                    let rev_next_hops = rev_flow.next_hops;
                    for nh in &mut fwd_next_hops{
                        nh.active_next_hop = 0;
                    }
                    self.local_flow_table.insert(fwd_key, fwd_next_hops.clone());
                    self.local_flow_table.insert(rev_key, rev_next_hops.clone());

                    let mut global_flow_table = self.global_flow_table.lock().unwrap();

                    if let Err(e) = global_flow_table.insert(fwd_key, fwd_next_hops[0],0){
                        log::error!("Failed to insert flow into global flow table: {}", e);
                    }
                    if let Err(e) = global_flow_table.insert(rev_key, rev_next_hops[0],0){
                        log::error!("Failed to insert flow into global flow table: {}", e);
                    }
                },
                FlowCommand::GetIfidxQueue { flow_key, tx } => {
                    if let Some(existing_flow_list) = self.local_flow_table.get(&flow_key){
                        if existing_flow_list.len() > 1{
                            let mut global_flow_table = self.global_flow_table.lock().unwrap();
                            let mut active_flow = global_flow_table.get(&flow_key, 0).unwrap();
                            if active_flow.packet_count < active_flow.max_packets{
                                tx.send(Some(active_flow)).unwrap();
                            } else {
                                active_flow.packet_count = 0;
                                let active_next_hop = active_flow.active_next_hop;
                                let next_active_next_hop_index = (active_next_hop + 1) % existing_flow_list.len() as u32;
                                let mut next_active_next_hop = existing_flow_list[next_active_next_hop_index as usize];
                                next_active_next_hop.active_next_hop = next_active_next_hop_index;
                                next_active_next_hop.packet_count = 0;
                                
                                global_flow_table.insert(&flow_key, next_active_next_hop, 0).unwrap();
                                info!("changed next_hop");
                                tx.send(Some(next_active_next_hop)).unwrap();
                            }
                        } else {
                            tx.send(Some(existing_flow_list[0])).unwrap();
                        }
                    } else {
                        tx.send(None).unwrap();
                    }
                },
            }
        }
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
        let res = self.tx.send(FlowCommand::AddFlow{fwd_rev_flow}).await.
            map_err(|e| anyhow::anyhow!("Failed to send add flow command: {}", e));
        if let Err(e) = res{
            error!("Failed to send add flow command: {}", e);
            return Err(e);
        }
        Ok(())
    }
    pub async fn get_ifidx_queue(&self, flow_key: FlowKey) -> anyhow::Result<Option<FlowNextHop>>{
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self.tx.send(FlowCommand::GetIfidxQueue{flow_key, tx}).await{
            error!("Failed to send get ifidx queue command: {}", e);
            return Err(anyhow::anyhow!("Failed to send get ifidx queue command: {}", e));
        }
        let res = rx.await.map_err(|e| anyhow::anyhow!("Failed to get ifidx queue: {}", e));
        if let Err(e) = res{
            error!("Failed to get ifidx: {}", e);
            return Err(e);
        } else {
            res
        
        }
    }
}

pub enum FlowCommand{
    AddFlow{
        fwd_rev_flow: FwdRevFlow,
    },
    GetIfidxQueue{
        flow_key: FlowKey,
        tx: tokio::sync::oneshot::Sender<Option<FlowNextHop>>,
    },
}

#[derive(Default)]
pub struct Flow{
    pub key: FlowKey,
    pub next_hops: Vec<FlowNextHop>,
}

impl Display for Flow{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Flow: key: {:?}, next_hops: {:?}", self.key, self.next_hops)
    }
}

#[derive(Default)]
pub struct FwdRevFlow{
    pub fwd: Flow,
    pub rev: Flow,
}

impl Display for FwdRevFlow{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FwdRevFlow: fwd: {}, rev: {}", self.fwd, self.rev)
    }
}

