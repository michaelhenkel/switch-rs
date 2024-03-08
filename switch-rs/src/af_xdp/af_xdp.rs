use core::{mem::MaybeUninit, num::NonZeroU32, ptr::NonNull};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use std::hash::Hash;
use pnet::packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, Packet};
use switch_rs_common::InterfaceQueue;
use tokio::sync::RwLock;
use xdpilone::{xdp::XdpDesc, DeviceQueue, RingRx, RingTx};
use aya::maps::{HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::{error, info};

use super::interface::interface::Interface;


//const BUFFER_SIZE: u32 = 1 << 15;
const BATCH_SIZE: u32 = 256;
const FRAME_SIZE: u32 = 1 << 12;
const HEADROOM: u32 = 1 << 8;
const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;
const BUFFER_SIZE: u32 = 1 << 24;
const THRESOLD_FACTOR: u32 = 4;
const RX_SIZE: u32 = 1 << 11;
const TX_SIZE: u32 = 1 << 14;
const RX_INTERVAL: u64 = 256;
const COMPLETE_INTERVAL: u64 = 32;
#[repr(align(4096))]
struct PacketMap(MaybeUninit<[u8; BUFFER_SIZE as usize]>);

#[derive(Clone)]
pub struct AfXdpClient{
    tx_map: HashMap<u32, HashMap<u32, tokio::sync::mpsc::Sender<Arc<RwLock<[u8]>>>>>,
}

impl AfXdpClient{
    pub fn new(tx_map: HashMap<u32, HashMap<u32,tokio::sync::mpsc::Sender<Arc<RwLock<[u8]>>>>>) -> Self{
        AfXdpClient{
            tx_map,
        }
    }
    pub async fn send(&mut self, ifidx: u32, queue_id: u32, buf: Arc<RwLock<[u8]>>) -> anyhow::Result<()>{
        if let Some(tx_map) = self.tx_map.get_mut(&ifidx){
            if let Some(tx) = tx_map.get_mut(&queue_id){
                tx.send(buf).await.unwrap();
            }
        }
        Ok(())
    }
}

pub struct AfXdp{
    client: AfXdpClient,
    interface_list: HashMap<u32, Interface>,
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
}

impl AfXdp{
    pub fn new(interface_list: HashMap<u32, Interface>, xsk_map: XskMap<MapData>, interface_queue_table: BpfHashMap<MapData, InterfaceQueue, u32>) -> Self{
        let mut rx_map = HashMap::new();
        let mut tx_map = HashMap::new();
        for (ifidx, _interface) in &interface_list{
            let mut rx_queue_map = HashMap::new();
            let mut tx_qeue_map = HashMap::new();
            for queue_id in 0.._interface.queues{
                let (tx, rx) = tokio::sync::mpsc::channel(10000);
                rx_queue_map.insert(queue_id, Arc::new(RwLock::new(rx)));
                tx_qeue_map.insert(queue_id,tx);
            }
            rx_map.insert(*ifidx, rx_queue_map);
            tx_map.insert(*ifidx, tx_qeue_map);
        }
        AfXdp{
            client: AfXdpClient::new(
                tx_map
            ),
            interface_list,
            xsk_map: Arc::new(Mutex::new(xsk_map)),
            interface_queue_table: Arc::new(Mutex::new(interface_queue_table)),
        }
    }
    pub fn client(&self) -> AfXdpClient{
        self.client.clone()
    }

    pub async fn run(&self, mac_table: BpfHashMap<MapData, [u8;6], u32>) -> anyhow::Result<()>{
        let mut queue_manager = QueueManager::new(
            self.interface_list.clone(), 
            self.xsk_map.clone(), 
            self.interface_queue_table.clone(),
            Arc::new(RwLock::new(mac_table)),
        );
        queue_manager.run().await.unwrap();
        Ok(())
    }
}

fn ifinfo(ifname: &str, queue_id: Option<u32>) -> Result<IfInfo, anyhow::Error> {
    let mut bytes = String::from(ifname);
    bytes.push('\0');
    let bytes = bytes.as_bytes();
    let name = core::ffi::CStr::from_bytes_with_nul(bytes).unwrap();

    let mut info = IfInfo::invalid();
    if let Err(e) = info.from_name(name){
        return Err(anyhow!("Failed to get interface info: {}", e));
    }
    if let Some(q) = queue_id {
        info.set_queue(q);
    }

    Ok(info)
}

struct QueueManager{
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
    interface_list: HashMap<u32, Interface>,
    mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
}

impl QueueManager{
    fn new(
        interface_list: HashMap<u32, Interface>,
        xsk_map: Arc<Mutex<XskMap<MapData>>>,
        interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
        mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
    ) -> Self{
        QueueManager{
            xsk_map,
            interface_queue_table,
            interface_list,
            mac_table,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()>{
        let mut queue_list = Vec::new();
        let mut queue_client_map = HashMap::new();
        let mut address_queue_map = HashMap::new();
        let mut ring_tx_map = HashMap::new();
        let mut fq_cq_map = HashMap::new();
        
        //let ring_rx_map = HashMap::new();
        let mut jh_list = Vec::new();
        {
            let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
            let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
            let mut umem_config = UmemConfig::default();
            umem_config.frame_size = FRAME_SIZE;
            let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();
            let mut rx_tx_config = SocketConfig {
                rx_size: NonZeroU32::new(RX_SIZE),
                tx_size: NonZeroU32::new(TX_SIZE),
                bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_SHARED_UMEM,
            };
            let mut idx = 0;
            let total_queues: u32 = self.interface_list.iter().map(|(_k,v)| v.queues).sum();
            let mut interface_queue_table = self.interface_queue_table.lock().unwrap();
            let mut xsk_map = self.xsk_map.lock().unwrap();
            for (_ifidx, interface) in &self.interface_list{
                for queue_id in 0..interface.queues{
                    let info = ifinfo(&interface.name, Some(queue_id)).unwrap();
                    let sock = if idx == 0{
                        Socket::with_shared(&info, &umem).unwrap()
                    } else {
                        rx_tx_config.bind_flags = SocketConfig::XDP_BIND_SHARED_UMEM;
                        Socket::new(&info).unwrap()
                    };
                    let mut fq_cq = umem.fq_cq(&sock).unwrap();
                    let rxtx = umem.rx_tx(&sock, &rx_tx_config).unwrap();
                    let ring_rx = rxtx.map_rx().unwrap();
                    let ring_tx = rxtx.map_tx().unwrap();
                    if let Err(e) = umem.bind(&rxtx){
                        error!("failed to bind umem: {}", e);
                    }
                    let mut frame_buffer = HashMap::new();
                    
                    info!("umem frames: {}", umem.len_frames());
                    info!("frame size: {}", FRAME_SIZE);
                    let frames_per_queue = umem.len_frames()/total_queues;
                    info!("frames per queue: {}", frames_per_queue);
                    let thresholds = frames_per_queue/THRESOLD_FACTOR;
                    info!("thresholds: {}", thresholds);
                    let queue_frame_start = frames_per_queue * idx;
                    let queue_frame_end = queue_frame_start + frames_per_queue;
                    info!("queue frame start: {}", queue_frame_start);
                    info!("queue frame end: {}", queue_frame_end);
                    for i in queue_frame_start..queue_frame_end{
                        let mut recv_frame = match umem.frame(BufIdx(i)){
                            Some(recv_frame) => recv_frame,
                            None => {
                                error!("failed to get frame from umem: {}", i);
                                break;
                            }
                        };
                        let recv_buf = unsafe { recv_frame.addr.as_mut() };
                        let interval_size = BUFFER_SIZE/total_queues;
                        let queue_index = recv_frame.offset/interval_size as u64;
                        let queue_index = queue_index.min(total_queues as u64-1);
                        frame_buffer.insert(recv_frame.offset, recv_buf);
                        address_queue_map.insert(queue_index, (interface.ifidx, queue_id));
                    }
                    {
                        let mut writer = fq_cq.fill(RX_SIZE);
                        writer.insert(frame_buffer.iter().map(|(addr, _d)| addr.clone()));
                        writer.commit();
                    }

                    let interface_queue = InterfaceQueue::new(interface.ifidx, queue_id);
                    interface_queue_table.insert(interface_queue, idx, 0).unwrap();
                    xsk_map.set(idx, ring_rx.as_raw_fd(), 0).unwrap();
                    idx += 1;
                    let queue = Queue::new(
                        (queue_frame_start  * FRAME_SIZE) as u64,
                        (queue_frame_end * FRAME_SIZE) as u64,
                        queue_id,
                        interface.ifidx,
                        self.interface_list.clone(),
                        self.mac_table.clone(),
                        thresholds,
                        total_queues,
                    );
                    info!("queue: {},{} pending {}", interface.ifidx, queue_id, fq_cq.pending());
                    ring_tx_map.insert((interface.ifidx, queue_id), Arc::new(Mutex::new(ring_tx)));
                    fq_cq_map.insert((interface.ifidx, queue_id), Arc::new(Mutex::new(fq_cq)));
                    queue_client_map.insert((interface.ifidx, queue_id), queue.client());
                    queue_list.push((queue, ring_rx, frame_buffer));
                }
            }

        }

        for (queue, ring_rx, frame_buffer) in queue_list{
            info!("starting queue: {},{}", queue.ifidx, queue.queue_id);
            info!("frame buffer len: {}", frame_buffer.len());
            info!("start: {} end: {}", queue.buf_start, queue.buf_end);
            info!("address queue map: {:?}", address_queue_map);
            let queue_client_map = queue_client_map.clone();
            let address_queue_map = address_queue_map.clone();
            let ring_tx_map = ring_tx_map.clone();
            let fq_cq_map = fq_cq_map.clone();
            let jh = tokio::spawn(async move{
                queue.run(frame_buffer, ring_rx, ring_tx_map, queue_client_map, address_queue_map, fq_cq_map).await.unwrap();
            });
            jh_list.push(jh);
        }

        futures::future::join_all(jh_list).await;

        Ok(())
    }
}

struct Queue{
    buf_start: u64,
    buf_end: u64,
    totol_queues: u32,
    sent_packets: u32,
    //received_packets: u32,
    //completed_packets: u32,
    thresholds: u32,
    queue_id: u32,
    ifidx: u32,
    client: QueueClient,
    sender_rx: Arc<RwLock<tokio::sync::mpsc::Receiver<QueueCommand>>>,
    sender2_rx: Arc<RwLock<tokio::sync::mpsc::Receiver<XdpDesc>>>,
    interface_list: HashMap<u32, Interface>,
    mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
}

impl Queue{
    fn new(
        buf_start: u64,
        buf_end: u64,
        queue_id: u32,
        ifidx: u32,
        interface_list: HashMap<u32, Interface>,
        mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
        thresholds: u32,
        totol_queues: u32,
    ) -> Self{
        let (sender_tx, sender_rx) = tokio::sync::mpsc::channel(100);
        let (sender2_tx, sender2_rx) = tokio::sync::mpsc::channel(100);
        Queue{
            buf_start,
            buf_end,
            totol_queues,
            sent_packets: 0,
            thresholds,
            queue_id,
            ifidx,
            client: QueueClient::new(sender_tx, sender2_tx),
            sender_rx: Arc::new(RwLock::new(sender_rx)),
            sender2_rx: Arc::new(RwLock::new(sender2_rx)),
            interface_list,
            mac_table,
        }
    }
    fn client(&self) -> QueueClient{
        self.client.clone()
    }

    pub async fn run(
        &self,
        mut frame_buffer: HashMap<u64, &'static mut [u8]>,
        mut ring_rx: RingRx,
        ring_tx_map: HashMap<(u32,u32), Arc<Mutex<RingTx>>>,
        queue_client_map: HashMap<(u32, u32), QueueClient>,
        address_queue_map: HashMap<u64, (u32, u32)>,
        fq_cq_map: HashMap<(u32,u32), Arc<Mutex<DeviceQueue>>>,
    ) -> anyhow::Result<()> {
        let mut jh_list = Vec::new();

        let queue_id = self.queue_id;
        let ifidx = self.ifidx;
        let queue_id_ifidx = format!{"{}:{}", ifidx, queue_id};
        let thresholds = self.thresholds;
        let total_queues_clone = self.totol_queues;
        let buf_start = self.buf_start;
        let buf_end = self.buf_end;

        let interface_list = self.interface_list.clone();
        let fq_cq_map_clone = fq_cq_map.clone();
        let mac_table = self.mac_table.clone();
        let address_queue_map_clone = address_queue_map.clone();

        let interface_list_clone = self.interface_list.clone();
        let jh = tokio::spawn(async move{
            let mut collect_interval = tokio::time::interval(Duration::from_micros(COMPLETE_INTERVAL));
            loop{
                collect_interval.tick().await;
                for (_, interface) in &interface_list_clone{
                    for queue_id in 0..interface.queues{
                        let queue_id_ifidx = format!{"{}:{}", interface.ifidx, queue_id};
                        let complete_map = getter(&fq_cq_map_clone, (interface.ifidx, queue_id)).
                            map(|fq_cq| complete(fq_cq, total_queues_clone, queue_id_ifidx.clone())).
                            unwrap().
                            unwrap();
                        for (queue_idx, addr_list) in complete_map{
                            if let Some((ifidx, queue_id)) = address_queue_map_clone.get(&queue_idx){
                                getter(&fq_cq_map_clone, (*ifidx, *queue_id)).map(|fq_cq| fill(fq_cq, addr_list, queue_id_ifidx.clone())).unwrap();
                            }
                        }
                    }
                }
            }
        });
        jh_list.push(jh);

        let fq_cq_map_clone = fq_cq_map.clone();
        let jh = tokio::spawn(async move{
            let mut receive_interval = tokio::time::interval(Duration::from_micros(RX_INTERVAL));
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            let mac_table = mac_table.read().await;
            let mut receive_counter = 0;
            let mut send_counter = 0;
            let mut drop_counter = 0;
            
            let mut send_map = HashMap::new();
            for interface in interface_list.values(){
                for queue_id in 0..interface.queues{
                    let desc_list: Vec<XdpDesc>  = Vec::with_capacity(BATCH_SIZE as usize);
                    send_map.insert((interface.ifidx, queue_id), desc_list);
                }
            }
            loop{
                if send_counter >= thresholds || receive_counter >= thresholds{
                    let pending_cnt = getter(&fq_cq_map_clone, (ifidx, queue_id)).map(|fq_cq| pending(fq_cq)).unwrap().unwrap();
                    let available_cnt = getter(&fq_cq_map_clone, (ifidx, queue_id)).map(|fq_cq| available(fq_cq)).unwrap().unwrap();
                    if pending_cnt <= thresholds{

                        drop_counter += pending_cnt;
                        info!("1 {} dropped {}, pending {}, available {}, threshold {}",queue_id_ifidx.clone(), drop_counter, pending_cnt, available_cnt, thresholds);
                        tokio::time::sleep(Duration::from_micros(COMPLETE_INTERVAL)).await;
                        let pending_cnt = getter(&fq_cq_map_clone, (ifidx, queue_id)).map(|fq_cq| pending(fq_cq)).unwrap().unwrap();
                        let available_cnt = getter(&fq_cq_map_clone, (ifidx, queue_id)).map(|fq_cq| available(fq_cq)).unwrap().unwrap();
                        info!("2 {} dropped {}, pending {}, available {}",queue_id_ifidx.clone(), drop_counter, pending_cnt, available_cnt);
                    }
                    receive_counter = 0;
                }
                let mut receiver = ring_rx.receive(BATCH_SIZE);
                let mut fill_list = Vec::new();
                //let mut batch_counter = 0;

                while let Some(desc) = receiver.read() {
                    receive_counter += 1;
                    //batch_counter += 1;

                    //info!("{} Received descriptor with address {}", queue_id_ifidx.clone(), desc.addr);
                    let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                    let offset = desc.addr - buf_idx;

                    if let Some(buf) = frame_buffer.get_mut(&buf_idx) {
                        let buf = &buf.as_ref()[offset as usize..];
                        let mut buf: [u8;PAYLOAD_SIZE as usize] = buf.try_into().unwrap();
                        if let Some(mut eth_packet) = MutableEthernetPacket::new(&mut buf){
                            match eth_packet.get_ethertype(){
                                EtherTypes::Arp => {
                                    if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()){
                                        let op = arp_packet.get_operation();
                                        match op{
                                            ArpOperations::Request => {
                                                for (_, interface) in &interface_list{
                                                    if interface.ifidx == ifidx{
                                                        continue;
                                                    }
                                                    let mac = interface.mac;
                                                    eth_packet.set_destination(mac.into());
                                                    eth_packet.set_source(interface.mac.into());
                                                    send_map.get_mut(&(interface.ifidx, queue_id)).unwrap().push(desc);
                                                }  
                                            },
                                            _ => {},
                                        }
                                    } else {
                                        fill_list.push(desc.addr);
                                        error!("failed to parse arp packet");
                                    }
                                },
                                EtherTypes::Ipv4 => {
                                    let dst_mac: [u8;6] = eth_packet.get_destination().into();
                                    let dst_ifidx = if let Some(dst_ifidx) = local_mac_table.get(&dst_mac){
                                        *dst_ifidx
                                    } else {
                                        if let Ok(dst_ifidx) = mac_table.get(&dst_mac.into(),0){
                                            local_mac_table.insert(dst_mac, dst_ifidx);
                                            dst_ifidx
                                        } else {
                                            fill_list.push(desc.addr);
                                            error!("failed to get dst ifidx");
                                            continue;
                                        }
                                    };
                                    send_map.get_mut(&(dst_ifidx, queue_id)).unwrap().push(desc);
                                },
                                _ => {
                                    fill_list.push(desc.addr);
                                    error!("failed to parse packet, not arp or ipv4 {:#?}", eth_packet);
                                }
                            }
                        } else {
                            fill_list.push(desc.addr);
                            error!("failed to parse ethernet packet");
                        }
                    } else {
                        fill_list.push(desc.addr);
                        error!("failed to get buffer for address {}", desc.addr);
                    }
                }
                /*
                if batch_counter > 0{
                    info!("{} batch received: {}", queue_id_ifidx, batch_counter);
                }
                */

                if fill_list.len() > 0{
                    getter(&fq_cq_map_clone, (ifidx, queue_id)).map(|fq_cq| fill(fq_cq, fill_list.clone(), queue_id_ifidx.clone())).unwrap();
                    fill_list.clear();
                }

                for ((ifidx, queue_id), desc_list) in &mut send_map{
                    if desc_list.len() == 0{
                        continue;
                    }
                    //info!("{} sending: {}", queue_id_ifidx, desc_list.len() as u32);
                    getter(&ring_tx_map, (*ifidx, *queue_id)).map(|ring_tx| send(desc_list, &ring_tx, queue_id_ifidx.clone())).unwrap();
                    send_counter += desc_list.len() as u32;
                    desc_list.clear();
                }


                receiver.release();
            }
        });
        jh_list.push(jh);
        
       


        /*
        let jh = tokio::spawn(async move{
            let mut interval = tokio::time::interval(Duration::from_nanos(2));
            loop{
                interval.tick().await;
                for (_, interface) in &interface_list{
                    for queue_id in 0..interface.queues{
                        let queue_id_ifidx = format!{"{}:{}", interface.ifidx, queue_id};
                        let complete_map = getter(&fq_cq_map_clone, (interface.ifidx, queue_id)).
                            map(|fq_cq| complete(fq_cq, total_queues_clone, queue_id_ifidx.clone())).
                            unwrap().
                            unwrap();
                        for (queue_idx, addr_list) in complete_map{
                            if let Some((ifidx, queue_id)) = address_queue_map_clone.get(&queue_idx){
                                getter(&fq_cq_map_clone, (*ifidx, *queue_id)).map(|fq_cq| fill(fq_cq, addr_list, queue_id_ifidx.clone())).unwrap();
                            }
                        }
                    }
                }

            }
        });
        jh_list.push(jh);

        */

        /* 
        let interface_list = self.interface_list.clone();
        let ifidx = self.ifidx;
        let queue_id = self.queue_id;
        let mac_table = self.mac_table.clone();
        let ring_tx_map = ring_tx_map.clone();
        let fq_cq_map = fq_cq.clone();
        //let queue_id_ifidx = queue_id_ifidx.clone();
        let jh = tokio::spawn(async move {
            let mut recv_interval = tokio::time::interval(Duration::from_nanos(10));
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            let mac_table = mac_table.read().await;
            let mut receive_counter = 0;
            let mut send_counter = 0;
            let mut drop_counter = 0;
            
            let mut send_map = HashMap::new();
            for interface in interface_list.values(){
                for queue_id in 0..interface.queues{
                    let desc_list: Vec<XdpDesc>  = Vec::with_capacity(BATCH_SIZE as usize);
                    send_map.insert((interface.ifidx, queue_id), desc_list);
                }
            }

            loop {
                recv_interval.tick().await;
                
                if send_counter >= thresholds || receive_counter >= thresholds{
                    let pending_cnt = getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| pending(fq_cq)).unwrap().unwrap();
                    let available_cnt = getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| available(fq_cq)).unwrap().unwrap();
                    if pending_cnt <= thresholds{
                        drop_counter += pending_cnt;
                        info!("1 {} dropped {}, pending {}, available {}, threshold {}",queue_id_ifidx.clone(), drop_counter, pending_cnt, available_cnt, thresholds);
                        let mut frame_start = buf_start/FRAME_SIZE as u64;
                        let frame_end = buf_end/FRAME_SIZE as u64;
                        frame_start += pending_cnt as u64;
                        let mut frame_list = Vec::new();
                        for i in frame_start..frame_end{
                            let addr = i * FRAME_SIZE as u64;
                            frame_list.push(addr);
                        }
                        getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| fill(fq_cq, frame_list, queue_id_ifidx.clone())).unwrap();
                        //continue;
                        let pending_cnt = getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| pending(fq_cq)).unwrap().unwrap();
                        let available_cnt = getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| available(fq_cq)).unwrap().unwrap();
                        info!("2 {} dropped {}, pending {}, available {}",queue_id_ifidx.clone(), drop_counter, pending_cnt, available_cnt);
                    }
                    receive_counter = 0;
                }
                let mut receiver = ring_rx.receive(BATCH_SIZE);
                let mut fill_list = Vec::new();
                //let mut batch_counter = 0;
                
                while let Some(desc) = receiver.read() {
                    receive_counter += 1;
                    //batch_counter += 1;

                    //info!("{} Received descriptor with address {}", queue_id_ifidx.clone(), desc.addr);
                    let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                    let offset = desc.addr - buf_idx;
                    
                    if let Some(buf) = frame_buffer.get_mut(&buf_idx) {
                        let buf = &buf.as_ref()[offset as usize..];
                        let mut buf: [u8;PAYLOAD_SIZE as usize] = buf.try_into().unwrap();
                        if let Some(mut eth_packet) = MutableEthernetPacket::new(&mut buf){
                            match eth_packet.get_ethertype(){
                                EtherTypes::Arp => {
                                    if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()){
                                        let op = arp_packet.get_operation();
                                        match op{
                                            ArpOperations::Request => {
                                                for (_, interface) in &interface_list{
                                                    if interface.ifidx == ifidx{
                                                        continue;
                                                    }
                                                    let mac = interface.mac;
                                                    eth_packet.set_destination(mac.into());
                                                    eth_packet.set_source(interface.mac.into());
                                                    send_map.get_mut(&(interface.ifidx, queue_id)).unwrap().push(desc);
                                                }  
                                            },
                                            _ => {},
                                        }
                                    } else {
                                        fill_list.push(desc.addr);
                                        error!("failed to parse arp packet");
                                    }
                                },
                                EtherTypes::Ipv4 => {
                                    let dst_mac: [u8;6] = eth_packet.get_destination().into();
                                    let dst_ifidx = if let Some(dst_ifidx) = local_mac_table.get(&dst_mac){
                                        *dst_ifidx
                                    } else {
                                        if let Ok(dst_ifidx) = mac_table.get(&dst_mac.into(),0){
                                            local_mac_table.insert(dst_mac, dst_ifidx);
                                            dst_ifidx
                                        } else {
                                            fill_list.push(desc.addr);
                                            error!("failed to get dst ifidx");
                                            continue;
                                        }
                                    };
                                    send_map.get_mut(&(dst_ifidx, queue_id)).unwrap().push(desc);
                                },
                                _ => {
                                    fill_list.push(desc.addr);
                                    error!("failed to parse packet, not arp or ipv4 {:#?}", eth_packet);
                                }
                            }
                        } else {
                            fill_list.push(desc.addr);
                            error!("failed to parse ethernet packet");
                        }
                    } else {
                        fill_list.push(desc.addr);
                        error!("failed to get buffer for address {}", desc.addr);
                    }
                }
                /*
                if batch_counter > 0{
                    info!("{} batch received: {}", queue_id_ifidx, batch_counter);
                }
                */

                if fill_list.len() > 0{
                    getter(&fq_cq_map, (ifidx, queue_id)).map(|fq_cq| fill(fq_cq, fill_list.clone(), queue_id_ifidx.clone())).unwrap();
                    fill_list.clear();
                }
                
                for ((ifidx, queue_id), desc_list) in &mut send_map{
                    if desc_list.len() == 0{
                        continue;
                    }
                    //info!("{} sending: {}", queue_id_ifidx, desc_list.len() as u32);
                    getter(&ring_tx_map, (*ifidx, *queue_id)).map(|ring_tx| send(desc_list, &ring_tx, queue_id_ifidx.clone())).unwrap();
                    send_counter += desc_list.len() as u32;
                    desc_list.clear();
                }


                receiver.release();
            }
        });
        jh_list.push(jh);
        */
        futures::future::join_all(jh_list).await;
        Ok(())
    }
    
}

fn getter<T, F>(map: &HashMap<T, F>, key: T) -> Option<&F>
where T: Hash, T: std::cmp::Eq
{
    map.get(&key).map(|v| v)
}

fn send(descriptors: &mut Vec<XdpDesc>, ring_tx: &Arc<Mutex<RingTx>>, queue_id_ifidx: String) -> anyhow::Result<()>{
    let mut ring_tx = ring_tx.lock().unwrap();
    {
        let mut writer = ring_tx.transmit(descriptors.len() as u32);
        writer.insert(descriptors.iter().map(|k| k.clone()));
        writer.commit();
    }
    if ring_tx.needs_wakeup(){
        ring_tx.wake();
    }
    //info!("{} sent: {}",queue_id_ifidx, descriptors.len());
    Ok(())
}

fn complete(fq_cq: &Arc<Mutex<DeviceQueue>>, total_queues: u32, queue_id_ifidx: String) -> anyhow::Result<HashMap<u64, Vec<u64>>>{
    let mut desc_map: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut fq_cq = fq_cq.lock().unwrap();
    let mut completed = 0;
    let available = fq_cq.available();
    {

        let mut reader = fq_cq.complete(available);
        while let Some(desc) = reader.read(){
            let desc = desc - HEADROOM as u64;
            //info!("{} Read descriptor with address: {}",queue_id_ifidx_clone, desc);
            let interval = BUFFER_SIZE/total_queues;
            let queue_idx = desc/interval as u64;
            let queue_idx = queue_idx.min(total_queues as u64-1);
            if let Some(desc_list) = desc_map.get_mut(&queue_idx){
                desc_list.push(desc);
            } else {
                let mut desc_list = Vec::new();
                desc_list.push(desc);
                desc_map.insert(queue_idx, desc_list);
            }
            completed += 1;
        }
        reader.release();
    }
    if completed > 0 || available > 0{
        //info!("{} completed/available: {}/{}",queue_id_ifidx, completed, available);
    }
    Ok(desc_map)
}

fn fill(fq_cq: &Arc<Mutex<DeviceQueue>>, desc_list: Vec<u64>, queue_id_ifidx: String) -> anyhow::Result<()>{
    let mut fq_cq = fq_cq.lock().unwrap();
    {
        let mut writer = fq_cq.fill(desc_list.len() as u32);
        writer.insert(desc_list.iter().map(|k| k.clone()));
        writer.commit();
    }
    //info!("{} filled: {}",queue_id_ifidx, desc_list.len());
    Ok(())
}

fn pending(fq_cq: &Arc<Mutex<DeviceQueue>>) -> anyhow::Result<u32>{
    let fq_cq = fq_cq.lock().unwrap();
    let pending = fq_cq.pending();
    Ok(pending)
}

fn available(fq_cq: &Arc<Mutex<DeviceQueue>>) -> anyhow::Result<u32>{
    let fq_cq = fq_cq.lock().unwrap();
    let available = fq_cq.available();
    Ok(available)
}

#[derive(Clone)]
struct QueueClient{
    sender_tx: tokio::sync::mpsc::Sender<QueueCommand>,
    sender2_tx: tokio::sync::mpsc::Sender<XdpDesc>,
}

impl QueueClient{
    fn new(sender_tx: tokio::sync::mpsc::Sender<QueueCommand>, sender2_tx: tokio::sync::mpsc::Sender<XdpDesc>) -> Self{
        QueueClient{
            sender_tx,
            sender2_tx,
        }
    }
    async fn send(&self, descriptor: XdpDesc) -> anyhow::Result<()>{
        self.sender2_tx.send(descriptor).await.unwrap();
        Ok(())
    }
    async fn complete(&self, count: u32) -> anyhow::Result<()>{
        self.sender_tx.send(QueueCommand::Complete(count)).await.unwrap();
        Ok(())
    }
    async fn fill(&self, desc_list: Vec<u64>) -> anyhow::Result<()>{
        self.sender_tx.send(QueueCommand::Fill(desc_list)).await.unwrap();
        Ok(())
    }
    async fn pending(&self) -> Option<u32>{
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        self.sender_tx.send(QueueCommand::Pending{tx}).await.unwrap();
        rx.recv().await
    }
}

enum QueueCommand{
    Complete(u32),
    Fill(Vec<u64>),
    Pending{
        tx: tokio::sync::mpsc::Sender<u32>
    }
}

enum CounterCommad{
    Sent(u32),
    Received,

    //Completed,
}

