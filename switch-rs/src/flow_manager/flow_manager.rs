use std::{collections::HashMap, sync::Arc};
use aya::maps::{HashMap as BpfHashMap, MapData};
use switch_rs_common::{FlowKey, FlowNextHop};
use tokio::sync::{mpsc::Receiver, RwLock};

pub struct FlowManager{
    rx: Arc<RwLock<Receiver<FlowCommand>>>,
    client: FlowManagerClient,
    global_flow_table: BpfHashMap<MapData, FlowKey, FlowNextHop>,
    local_flow_table: HashMap<FlowKey, Vec<FlowNextHop>>,
}

impl FlowManager{
    pub fn new(global_flow_table: BpfHashMap<MapData, FlowKey, FlowNextHop>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let client = FlowManagerClient::new(tx.clone());
        FlowManager{
            rx: Arc::new(RwLock::new(rx)),
            client,
            global_flow_table,
            local_flow_table: HashMap::new(),
        }
    }
    pub async fn run(&mut self){
        let mut rx = self.rx.write().await;
        while let Some(cmd) = rx.recv().await{
            match cmd{
                FlowCommand::AddFlow { fwd_rev_flow } => {
                    let fwd_flow = fwd_rev_flow.fwd;
                    let rev_flow = fwd_rev_flow.rev;
                    let fwd_key = fwd_flow.key;
                    let rev_key = rev_flow.key;
                    let mut fwd_next_hops = fwd_flow.next_hops;
                    let rev_next_hops = rev_flow.next_hops;
                    for nh in &mut fwd_next_hops{
                        nh.active_next_hop = 0;
                    }
                    self.local_flow_table.insert(fwd_key, fwd_next_hops.clone());
                    self.local_flow_table.insert(rev_key, rev_next_hops.clone());

                    if let Err(e) = self.global_flow_table.insert(fwd_key, fwd_next_hops[0],0){
                        log::error!("Failed to insert flow into global flow table: {}", e);
                    }
                    if let Err(e) = self.global_flow_table.insert(rev_key, rev_next_hops[0],0){
                        log::error!("Failed to insert flow into global flow table: {}", e);
                    }
                },
                FlowCommand::GetIfidxQueue { flow_key, tx } => {
                    if let Some(existing_flow_list) = self.local_flow_table.get(&flow_key){
                        if existing_flow_list.len() > 0{
                            let active_flow = self.global_flow_table.get(&flow_key, 0).unwrap();
                            let active_next_hop = active_flow.active_next_hop;
                            let next_active_next_hop_index = (active_next_hop + 1) % existing_flow_list.len() as u32;
                            let mut next_active_next_hop = existing_flow_list[next_active_next_hop_index as usize];
                            next_active_next_hop.active_next_hop = next_active_next_hop_index;
                            next_active_next_hop.packet_count = 0;
                            let _ = self.global_flow_table.insert(&flow_key, next_active_next_hop, 0);
                        } else {
                            let _ = tx.send(Some((existing_flow_list[0].ifidx, existing_flow_list[0].queue_id)));
                        }
                    } else {
                        let _ = tx.send(None);
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