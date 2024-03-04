use core::{mem::MaybeUninit, num::NonZeroU32, ptr::NonNull};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use kanal;
use pnet::{datalink::EtherType, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, Packet}};
use switch_rs_common::InterfaceQueue;
use tokio::sync::{mpsc::error, RwLock};
use xdpilone::{xdp::XdpDesc, DeviceQueue, RingRx, RingTx};
use aya::maps::{queue, HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::{error, info};
use crate::af_xdp::interface::interface;

use super::interface::interface::Interface;


//const BUFFER_SIZE: u32 = 1 << 15;
const BATCH_SIZE: u32 = 64;
const FRAME_SIZE: u32 = 1 << 12;
const TOTAL_NUMBER_OF_FRAMES: u32 = BUFFER_SIZE/FRAME_SIZE;
const HEADROOM: u32 = 1 << 8;
const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;
const BUFFER_SIZE: u32 = 1 << 23;
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
    rx_map: HashMap<u32, HashMap<u32,Arc<RwLock<tokio::sync::mpsc::Receiver<Arc<RwLock<[u8]>>>>>>>,
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
            rx_map
        }
    }
    pub fn client(&self) -> AfXdpClient{
        self.client.clone()
    }

    pub async fn run2(&self, mac_table: BpfHashMap<MapData, [u8;6], u32>) -> anyhow::Result<()>{
        let mut queue_manager = QueueManager::new(
            self.interface_list.clone(), 
            self.xsk_map.clone(), 
            self.interface_queue_table.clone(),
            Arc::new(RwLock::new(mac_table)),
        );
        queue_manager.run().await.unwrap();
        Ok(())
    }

    pub async fn run(&mut self, recv_tx: tokio::sync::mpsc::Sender<(u32, Arc<RwLock<[u8]>>)>, mac_table: BpfHashMap<MapData, [u8;6], u32>,) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>>{
        
        let mut rx_map = self.rx_map.clone();
        let interface_list = self.interface_list.clone();

        let mut jh_list = Vec::new();

        let idx = 0;
        let xsk_map = self.xsk_map.clone();
        let interface_queue_table = self.interface_queue_table.clone();
        let jh = tokio::spawn(async move{
            runner(interface_list, xsk_map, interface_queue_table, mac_table, idx, ).await.unwrap();
        });
        jh_list.push(jh);

        Ok(jh_list)
    }
}

#[derive(Default)]
struct Counters{
    total_recv: u32,
    total_send: u32,
    recv: u32,
    send: u32,
}

impl Counters{
    fn inc_total_recv(&mut self){
        self.total_recv += 1;
    }
    fn inc_total_send(&mut self){
        self.total_send += 1;
    }
    fn inc_recv(&mut self){
        self.recv += 1;
    }
    fn inc_send(&mut self){
        self.send += 1;
    }
    fn inc(&mut self){
        self.recv += 1;
        self.send += 1;
        self.total_recv += 1;
        self.total_send += 1;
    }
    fn reset_recv(&mut self){
        self.recv = 0;
    }
    fn reset_send(&mut self){
        self.send = 0;
    }
}

pub async fn runner(
    interfaces: HashMap<u32,Interface>,
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
    mac_table: BpfHashMap<MapData, [u8;6], u32>,
    mut idx: u32,
) -> anyhow::Result<()>{
    const FRAMES: u32 = 64;
    const FRAME_SIZE: u32 = 1 << 12;
    const HEADROOM: u32 = 1 << 8;
    const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;


    struct InterfaceQueueRes<'a>{
        rx: HashMap<(u32, u32), Rx<'a>>,
    }

    struct Rx<'a>{
        ring_rx: RingRx,
        recv_frame_buffer_list: HashMap<u64, &'a mut [u8]>,
        interface: Interface,
        thresholds: u32,
    }

    let counters = Arc::new(RwLock::new(Counters::default()));
    let mac_table_mutex = Arc::new(RwLock::new(mac_table));

    let (res, ring_tx_map, dq_map) = {
        let mut dq_map = HashMap::new();
        let mut ring_tx_map = HashMap::new();
        let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
        let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
        let mut umem_config = UmemConfig::default();
        umem_config.frame_size = FRAME_SIZE;
        let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();
        let mut interface_queue_res = InterfaceQueueRes{
            rx: HashMap::new(),
        };

        info!("interfaces: {:?}", interfaces);
        let mut interface_list: Vec<(Interface, u32)> = interfaces.iter().map(|(_k,v)| (v.clone(), v.queues)).collect();
        interface_list.sort_by_key(|(v,_)| v.ifidx);
        info!("interface list: {:?}", interface_list);
        let mut rx_tx_config = SocketConfig {
            rx_size: NonZeroU32::new(1 << 11),
            tx_size: NonZeroU32::new(1 << 14),
            bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_SHARED_UMEM,
        };

        let mut xsk_map = xsk_map.lock().unwrap();
        let mut interface_queue_table = interface_queue_table.lock().unwrap();

        for (list_idx, (interface, queue_id)) in interface_list.iter().enumerate(){
            info!("list_idx: {}, interface: {}, queue: {}", list_idx, interface.ifidx, queue_id);
            idx = idx * interface.queues;
            for queue_id in 0..interface.queues{
                info!("creating socket for interface: {}, queue: {}", interface.ifidx, queue_id);
                let info = ifinfo(&interface.name, Some(queue_id)).unwrap();
                let sock = if list_idx == 0 && queue_id == 0{
                    Socket::with_shared(&info, &umem).unwrap()
                } else {
                    rx_tx_config.bind_flags = SocketConfig::XDP_BIND_SHARED_UMEM;
                    Socket::new(&info).unwrap()
                };
                //let sock = Socket::with_shared(&info, &umem).unwrap();
                let mut fq_cq = umem.fq_cq(&sock).unwrap();


                let rxtx = umem.rx_tx(&sock, &rx_tx_config).unwrap();


                let ring_rx = rxtx.map_rx().unwrap();
                let ring_tx = rxtx.map_tx().unwrap();

                if let Err(e) = umem.bind(&rxtx){
                    error!("failed to bind umem: {}", e);
                }

                let mut recv_frame_buffer_list = HashMap::new();
                info!("umem frames: {}", umem.len_frames());
                let thresholds = umem.len_frames()/2;

                for i in 0..umem.len_frames(){
                    let mut recv_frame = match umem.frame(BufIdx(i)){
                        Some(recv_frame) => recv_frame,
                        None => {
                            error!("failed to get frame from umem: {}", i);
                            break;
                        }
                    };
                    let recv_buf = unsafe { recv_frame.addr.as_mut() };
                    recv_frame_buffer_list.insert(recv_frame.offset, recv_buf);
                }
                {
                    let mut writer = fq_cq.fill(1 << 14);
                    writer.insert(recv_frame_buffer_list.iter().map(|(addr, _d)| addr.clone()));
                    writer.commit();
                }

                let mut send_frame_buffer_list = HashMap::new();
                for i in 0..umem.len_frames(){
                    //idx = i + buf_idx_counter;
                    let mut send_frame = match umem.frame(BufIdx(i)){
                        Some(send_frame) => send_frame,
                        None => {
                            error!("failed to get frame from umem: {}", i);
                            break;
                        }
                    };
                    let send_buf = unsafe { send_frame.addr.as_mut() };
                    send_frame_buffer_list.insert(send_frame.offset, send_buf);
                }

                let interface_queue = InterfaceQueue::new(interface.ifidx, queue_id);
                interface_queue_table.insert(interface_queue, idx, 0).unwrap();
                xsk_map.set(idx, ring_rx.as_raw_fd(), 0).unwrap();
                idx += 1;

                let rx = Rx{
                    ring_rx,
                    recv_frame_buffer_list,
                    thresholds,
                    interface: interface.clone(),
                };

                ring_tx_map.insert((interface.ifidx, queue_id), ring_tx);
                dq_map.insert((interface.ifidx, queue_id), fq_cq);

                interface_queue_res.rx.insert((interface.ifidx, queue_id), rx);

                
            }
        }
        (interface_queue_res, Arc::new(Mutex::new(ring_tx_map)), Arc::new(Mutex::new(dq_map)))
    };


    
    let mut jh_list = Vec::new();
    for ((ifidx, queue_id), mut rx) in res.rx{
        let ring_tx_map = ring_tx_map.clone();
        let dq_map = dq_map.clone();
        let interface_list = interfaces.clone();
        let counters = counters.clone();
        let mac_table_mutex = mac_table_mutex.clone();
        let jh = tokio::spawn(async move{
            //let mac_table_mutex = mac_table_mutex.clone();
            let mut rcv_interval = tokio::time::interval(Duration::from_nanos(10));
            let mut desc_list = Vec::new();
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            let prefix = format!("{}:{}", ifidx, queue_id);
            loop{
                rcv_interval.tick().await;
                let mut receiver = rx.ring_rx.receive(FRAMES);
                let mut counters = counters.write().await;
                //if receiver.capacity() > 0 {
                    while let Some(desc) = receiver.read(){
                        info!("{} received: {}",prefix, counters.total_recv);
                        let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                        let offset = desc.addr - buf_idx;
                        if let Some(buf) = rx.recv_frame_buffer_list.get_mut(&buf_idx){
                            let d = &buf.as_ref()[offset as usize..];
                            let mut b: [u8;PAYLOAD_SIZE as usize] = d.try_into().unwrap();
                            let eth_arp = handle_packet(&mut b).unwrap().unwrap();
                            match eth_arp{
                                EthArp::Arp(mut packet) => {
                                    //info!("{} arp request: {:?}",prefix, packet);
                                    for (_, interface) in &interface_list{
                                        if interface.ifidx == ifidx{
                                            continue;
                                        }
                                        let mac = interface.mac;
                                        packet.set_destination(mac.into());
                                        packet.set_source(interface.mac.into());

                                        send(ring_tx_map.clone(), desc, interface.ifidx, queue_id).unwrap();
                                        counters.inc();
                                        info!("{} send: {}, threshold: {}",prefix, counters.total_send, rx.thresholds);
                                        if counters.send >= rx.thresholds{
                                            info!("{} send threshold reached: {}, total send {}",prefix, counters.send, counters.total_send);
                                            complete(dq_map.clone(), counters.send, interface.ifidx, queue_id).unwrap();
                                            counters.reset_send();
                                        }

                                    }
                                },
                                EthArp::Eth(packet) => {
                                    let dst_mac: [u8;6] = packet.get_destination().into();
                                    if let Some(dst_ifidx) = local_mac_table.get(&dst_mac){
                                        send(ring_tx_map.clone(), desc, *dst_ifidx, queue_id).unwrap();
                                        counters.inc();
                                        info!("{} send: {}, threshold: {}",prefix, counters.total_send, rx.thresholds);
                                        if counters.send >= rx.thresholds{
                                            info!("{} send threshold reached: {}, total send {}",prefix, counters.send, counters.total_send);
                                            complete(dq_map.clone(), counters.send, *dst_ifidx, queue_id).unwrap();
                                            counters.reset_send();
                                        }
                                    } else {
                                        let mac_table = mac_table_mutex.read().await;
                                        let dst_ifidx = if let Ok(dst_ifidx) = mac_table.get(&dst_mac.into(),0){
                                            local_mac_table.insert(dst_mac, dst_ifidx);
                                            dst_ifidx
                                        } else {
                                            continue;
                                        };
                                        send(ring_tx_map.clone(), desc, dst_ifidx, queue_id).unwrap();
                                        counters.inc();
                                        info!("{} send: {}, threshold: {}",prefix, counters.total_send, rx.thresholds);
                                        if counters.send >= rx.thresholds{
                                            info!("{} send threshold reached: {}, total send {}",prefix, counters.send, counters.total_send);
                                            complete(dq_map.clone(), counters.send, dst_ifidx, queue_id).unwrap();
                                            counters.reset_send();
                                        }
                                    }
                                },
                            }
                        }
                        desc_list.push(desc.addr);
                    }
                //}
                receiver.release();
                //info!("{} rcv: {}, threshold: {}",prefix, counters.total_recv, rx.thresholds);
                if counters.recv >= rx.thresholds{
                    info!("{} recv threshold reached: {}, total recv {}",prefix, counters.recv, counters.total_recv);
                    fill(dq_map.clone(), desc_list.clone(), rx.interface.ifidx, queue_id).unwrap();
                    //wake(dq_map.clone(), rx.interface.ifidx, queue_id).unwrap();
                    desc_list.clear();
                    counters.reset_recv();
                }
            }
        });
        jh_list.push(jh);
    }
    futures::future::join_all(jh_list).await;
    Ok(())
}

fn handle_packet(packet: &mut [u8]) -> anyhow::Result<Option<EthArp>>{
    let eth_packet = MutableEthernetPacket::new(packet).ok_or(anyhow::anyhow!("failed to parse Ethernet packet"))?;
    match eth_packet.get_ethertype(){
        EtherTypes::Arp => {
            let arp_packet = ArpPacket::new(eth_packet.payload()).ok_or(anyhow::anyhow!("failed to parse ARP packet"))?;
            let op = arp_packet.get_operation();
            //info!("arp packet: {:?}", arp_packet);
            match op{
                ArpOperations::Request => {
                    return Ok(Some(EthArp::Arp(eth_packet)));
                },
                _ => {},
            }
        },
        EtherTypes::Ipv4 => {
            return Ok(Some(EthArp::Eth(eth_packet)));
        },
        _ => {
            //info!("eth packet: {:?}", eth_packet);
        }
    }
    Ok(None)
}

enum EthArp<'a>{
    Arp(MutableEthernetPacket<'a>),
    Eth(MutableEthernetPacket<'a>),
}


fn send(
    ring_tx_map: Arc<Mutex<HashMap<(u32,u32),RingTx>>>,
    desc: XdpDesc, 
    ifidx: u32,
    queue_id: u32,
) -> anyhow::Result<()>{
    let mut ring_tx = ring_tx_map.lock().unwrap();
    let ring_tx = ring_tx.get_mut(&(ifidx, queue_id)).unwrap();
    {
        let mut writer = ring_tx.transmit(1);
        writer.insert_once(desc);
        writer.commit();
    }
    if ring_tx.needs_wakeup(){
        ring_tx.wake();
    }
    Ok(())
}

fn complete(
    dq_map: Arc<Mutex<HashMap<(u32,u32),DeviceQueue>>>,
    send_packet_counter: u32,
    ifidx: u32,
    queue_id: u32,
) -> anyhow::Result<()>{
    let mut dq = dq_map.lock().unwrap();
    let dq = dq.get_mut(&(ifidx, queue_id)).unwrap();
    let mut desc_list = Vec::new();
    {
        let mut reader = dq.complete(send_packet_counter);
        while let Some(desc) = reader.read(){
            desc_list.push(desc);
        }
        reader.release();
    }
    {
        info!("filling: {}, available: {}, pending {}", desc_list.len() as u32, dq.available(), dq.pending());
        let mut writer = dq.fill(desc_list.len() as u32);
        writer.insert(desc_list.iter().map(|k| k.clone()));
        writer.commit();
    }
    Ok(())
}

fn wake(
    dq_map: Arc<Mutex<HashMap<(u32,u32),DeviceQueue>>>,
    ifidx: u32,
    queue_id: u32,
) -> anyhow::Result<()>{
    let mut dq = dq_map.lock().unwrap();
    let dq = dq.get_mut(&(ifidx, queue_id)).unwrap();
    //if dq.needs_wakeup(){
        info!("wake up");
        dq.wake();
    //}
    Ok(())
}

fn fill(
    dq_map: Arc<Mutex<HashMap<(u32,u32),DeviceQueue>>>,
    desc_list: Vec<u64>,
    ifidx: u32,
    queue_id: u32,
) -> anyhow::Result<()>{
    let mut dq = dq_map.lock().unwrap();
    let dq = dq.get_mut(&(ifidx, queue_id)).unwrap();
    info!("filling: {}, available: {}, pending {}", desc_list.len() as u32, dq.available(), dq.pending());
    let mut writer = dq.fill(desc_list.len() as u32);
    
    writer.insert(desc_list.iter().map(|k| k.clone()));
    writer.commit();
    Ok(())
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
        let mut jh_list = Vec::new();
        {
            let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
            let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
            let mut umem_config = UmemConfig::default();
            umem_config.frame_size = FRAME_SIZE;
            let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();
            let mut rx_tx_config = SocketConfig {
                rx_size: NonZeroU32::new(1 << 11),
                tx_size: NonZeroU32::new(1 << 14),
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
                    let frames_per_queue = umem.len_frames()/total_queues;
                    info!("frames per queue: {}", frames_per_queue);
                    let thresholds = frames_per_queue/2;
                    let queue_frame_start = frames_per_queue * idx;
                    let queue_frame_end = queue_frame_start + frames_per_queue;
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
                        let mut writer = fq_cq.fill(1 << 14);
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
                        interface.mac,
                        self.interface_list.clone(),
                        self.mac_table.clone(),
                        thresholds,
                        total_queues,
                    );
                    queue_client_map.insert((interface.ifidx, queue_id), queue.client());
                    queue_list.push((queue, ring_rx, ring_tx, frame_buffer, fq_cq));
                }
            }

        }

        // 0, 4096, 8192, 12288 = 0
        // 16384, 20480, 24576, 28672 = 1
        // 32768, 36864, 40960, 45056 = 2
        // 49152, 53248, 57344, 61440 = 3



        for (queue, ring_rx, ring_tx, frame_buffer, fq_cq) in queue_list{
            info!("starting queue: {},{}", queue.ifidx, queue.queue_id);
            info!("frame buffer len: {}", frame_buffer.len());
            info!("start: {} end: {}", queue.buf_start, queue.buf_end);
            info!("address queue map: {:?}", address_queue_map);
            {
                info!("available: {}, pending: {}", fq_cq.available(), fq_cq.pending());
            }
            let queue_client_map = queue_client_map.clone();
            let address_queue_map = address_queue_map.clone();
            let jh = tokio::spawn(async move{
                queue.run(frame_buffer, ring_rx, ring_tx, queue_client_map, address_queue_map, fq_cq).await.unwrap();
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
    sent_descriptors: HashMap<u64, XdpDesc>,
    sent_packets: u32,
    received_packets: u32,
    completed_packets: u32,
    thresholds: u32,
    queue_id: u32,
    ifidx: u32,
    mac: [u8;6],
    client: QueueClient,
    sender_rx: Arc<RwLock<tokio::sync::mpsc::Receiver<QueueCommand>>>,
    interface_list: HashMap<u32, Interface>,
    mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
}

impl Queue{
    fn new(
        buf_start: u64,
        buf_end: u64,
        queue_id: u32,
        ifidx: u32,
        mac: [u8;6],
        interface_list: HashMap<u32, Interface>,
        mac_table: Arc<RwLock<BpfHashMap<MapData, [u8;6], u32>>>,
        thresholds: u32,
        totol_queues: u32,
    ) -> Self{
        let (sender_tx, sender_rx) = tokio::sync::mpsc::channel(10000);
        Queue{
            buf_start,
            buf_end,
            totol_queues,
            sent_descriptors: HashMap::new(),
            sent_packets: 0,
            received_packets: 0,
            completed_packets: 0,
            thresholds,
            queue_id,
            ifidx,
            mac,
            client: QueueClient::new(sender_tx),
            sender_rx: Arc::new(RwLock::new(sender_rx)),
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
        mut ring_tx: RingTx,
        queue_client_map: HashMap<(u32, u32), QueueClient>,
        address_queue_map: HashMap<u64, (u32, u32)>,
        mut fq_cq: DeviceQueue,
    ) -> anyhow::Result<()> {
        let mut jh_list = Vec::new();

        let queue_id = self.queue_id;
        let ifidx = self.ifidx;
        let queue_id_ifidx = format!{"{}:{}", ifidx, queue_id};
        
        let (counter_tx, mut counter_rx) = tokio::sync::mpsc::channel(10000);



        let mut sent_packets = self.sent_packets;
        let mut received_packets = self.received_packets;
        let mut completed_packets = self.completed_packets;
        let queue_id_ifidx_clone = queue_id_ifidx.clone();
        let thresholds = self.thresholds;
        let queue_client_map_clone = queue_client_map.clone();
        let jh = tokio::spawn(async move{
            let mut current_received = 0;
            while let Some(counter_command) = counter_rx.recv().await{
                match counter_command{
                    CounterCommad::Sent => {
                        sent_packets += 1;
                    },
                    CounterCommad::Received => {
                        received_packets += 1;
                        current_received += 1;
                    },
                    CounterCommad::Completed => {
                        completed_packets += 1;
                    },

                }
                if sent_packets >= thresholds{
                    //info!("{} Sent threshold reached: {}, total sent: {}", queue_id_ifidx_clone, thresholds, sent_packets);
                    for (_, queue_client) in &queue_client_map_clone{
                        queue_client.complete(sent_packets).await.unwrap();
                    }
                    sent_packets = 0;
                }
            }

            
        });
        jh_list.push(jh);

        let queue_id_ifidx_clone = queue_id_ifidx.clone();
        let sender_rx = self.sender_rx.clone();
        let queue_client_map_clone = queue_client_map.clone();
        let counter_tx_clone = counter_tx.clone();
        let total_queues_clone = self.totol_queues;
        let jh = tokio::spawn(async move {
            let mut sender_rx = sender_rx.write().await;
            while let Some(queue_command) = sender_rx.recv().await {
                match queue_command{
                    QueueCommand::Send(desc) => {
                        //info!("{} Sending descriptor with address: {}",queue_id_ifidx_clone, desc.addr);
                        {
                            let mut writer = ring_tx.transmit(1);
                            writer.insert_once(desc);
                            writer.commit();
                        }
                        if ring_tx.needs_wakeup(){
                            ring_tx.wake();
                        }
                        counter_tx_clone.send(CounterCommad::Sent).await.unwrap();
                    },
                    QueueCommand::Complete(count) => {
                        //info!("{} Completing request for {} descriptors",queue_id_ifidx_clone, count);
                        let mut desc_map: HashMap<u64, Vec<u64>> = HashMap::new();
                        {
                            let mut reader = fq_cq.complete(count);
                            while let Some(desc) = reader.read(){
                                let desc = desc - HEADROOM as u64;
                                //info!("{} Read descriptor with address: {}",queue_id_ifidx_clone, desc);
                                let interval = BUFFER_SIZE/total_queues_clone;
                                let queue_idx = desc/interval as u64;
                                let queue_idx = queue_idx.min(total_queues_clone as u64-1);
                                if let Some(desc_list) = desc_map.get_mut(&queue_idx){
                                    desc_list.push(desc);
                                } else {
                                    let mut desc_list = Vec::new();
                                    desc_list.push(desc);
                                    desc_map.insert(queue_idx, desc_list);
                                }
                            }
                            reader.release();
                        }
                        //info!("{} desc_amp: {:?}", queue_id_ifidx_clone, desc_map);
                        let desc_map_len = desc_map.len();
                        if desc_map_len > 0 {
                            for (queue_idx, desc_list) in desc_map{
                                //info!("{} queue_idx: {} address_list {:?}", queue_id_ifidx_clone, queue_idx, desc_list);
                                if let Some((ifidx, queue_id)) = address_queue_map.get(&queue_idx){
                                    if let Some(queue_client) = queue_client_map_clone.get(&(*ifidx, *queue_id)){
                                        //info!("Sending fill request to {}/{} for {:?} descriptors", ifidx, queue_id, desc_list);
                                        queue_client.fill(desc_list).await.unwrap();
                                    } else {
                                        error!("{} failed to get queue client", queue_id_ifidx_clone);
                                    }
                                } else {
                                    error!("{} failed to get ifidx and queue_id for idx {}", queue_id_ifidx_clone, queue_idx);
                                }
                            }
                            //info!("{} Completed request for {} descriptors",queue_id_ifidx_clone, desc_map_len);
                        }
                    },
                    QueueCommand::Fill(desc_list) => {
                        /*
                        info!("{} Filling: {}", queue_id_ifidx_clone, desc_list.len());
                        info!("{} available: {}", queue_id_ifidx_clone, fq_cq.available());
                        info!("{} pending: {}", queue_id_ifidx_clone, fq_cq.pending());
                        */
                        {
                            let mut writer = fq_cq.fill(desc_list.len() as u32);
                            writer.insert(desc_list.iter().map(|k| k.clone()));
                            writer.commit();
                        }
                        /*
                        info!("{} available: {}", queue_id_ifidx_clone, fq_cq.available());
                        info!("{} pending: {}", queue_id_ifidx_clone, fq_cq.pending());
                        */
                    },
                }
            }
        });
        jh_list.push(jh);

        let interface_list = self.interface_list.clone();
        let ifidx = self.ifidx;
        let queue_id = self.queue_id;
        let mac_table = self.mac_table.clone();
        let counter_tx_clone = counter_tx.clone();
        let queue_id_ifidx = queue_id_ifidx.clone();
        let jh = tokio::spawn(async move {
            let mut recv_interval = tokio::time::interval(Duration::from_nanos(5));
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            let mac_table = mac_table.read().await;
            loop {
                recv_interval.tick().await;
                let mut receiver = ring_rx.receive(BATCH_SIZE);
                while let Some(desc) = receiver.read() {
                    //info!("{} Received descriptor with address {}", queue_id_ifidx.clone(), desc.addr);
                    counter_tx_clone.send(CounterCommad::Received).await.unwrap();
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
                                                    if let Some(queue_client) = queue_client_map.get(&(interface.ifidx, queue_id)){
                                                        if let Err(e) = queue_client.send(desc).await{
                                                            error!("failed to send to queue client: {}", e);
                                                        }
                                                    } else {
                                                        error!("failed to get queue client");
                                                    }
                                                }  
                                            },
                                            _ => {},
                                        }
                                    } else {
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
                                            error!("failed to get dst ifidx");
                                            continue;
                                        }
                                    };
                                    if let Some(queue_client) = queue_client_map.get(&(dst_ifidx, queue_id)){
                                        if let Err(e) = queue_client.send(desc).await{
                                            error!("failed to send to queue client: {}", e);
                                        }
                                    } else {
                                        error!("failed to get queue client");
                                    }
                                },
                                _ => {
                                    error!("failed to parse packet, not arp or ipv4 {:#?}", eth_packet);
                                }
                            }
                        } else {
                            error!("failed to parse ethernet packet");
                        }
                    } else {
                        error!("failed to get buffer for address {}", desc.addr);
                    }
                }
                receiver.release();
            }
        });
        jh_list.push(jh);
        futures::future::join_all(jh_list).await;
        Ok(())
    }
    
}

#[derive(Clone)]
struct QueueClient{
    sender_tx: tokio::sync::mpsc::Sender<QueueCommand>,
}

impl QueueClient{
    fn new(sender_tx: tokio::sync::mpsc::Sender<QueueCommand>) -> Self{
        QueueClient{
            sender_tx
        }
    }
    async fn send(&self, descriptor: XdpDesc) -> anyhow::Result<()>{
        self.sender_tx.send(QueueCommand::Send(descriptor)).await.unwrap();
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
}

enum QueueCommand{
    Send(XdpDesc),
    Complete(u32),
    Fill(Vec<u64>),
}

enum CounterCommad{
    Sent,
    Received,
    Completed,
}

