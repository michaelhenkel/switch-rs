use core::{num::NonZeroU32, ptr::NonNull};
use std::{cell::UnsafeCell, collections::{HashMap, VecDeque},sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use async_trait::async_trait;
use pnet::packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, Packet};
use switch_rs_common::InterfaceQueue;
use tokio::sync::{RwLock, RwLockWriteGuard};
use xdpilone::{xdp::XdpDesc, DeviceQueue, RingRx, RingTx, WriteFill};
use aya::maps::{HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::{error, info};
use super::interface::interface::Interface;

//const BUFFER_SIZE: u32 = 1 << 16;
const BATCH_SIZE: u32 = 256;
const FRAME_SIZE: u32 = 1 << 12;
const HEADROOM: u32 = 1 << 8;
//const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;
const BUFFER_SIZE: u32 = 1 << 26;
const THRESOLD_FACTOR: u32 = 8;
const RX_INTERVAL: u64 = 500;
const COMPLETE_INTERVAL: u64 = 10;
#[repr(align(4096))]
struct PacketMap(UnsafeCell<[u8; BUFFER_SIZE as usize]>);

unsafe impl Sync for PacketMap {}
unsafe impl Send for PacketMap {}

static MEM: PacketMap = PacketMap(UnsafeCell::new([0; BUFFER_SIZE as usize]));

struct MyDeviceQueue(DeviceQueue);
unsafe impl Send for MyDeviceQueue {}
unsafe impl Sync for MyDeviceQueue {}

struct SafeDeviceQueue {
    inner: Mutex<MyDeviceQueue>,
}

impl SafeDeviceQueue {
    pub fn fill(&mut self, desc_list: &mut VecDeque<u64>, failed: &mut VecDeque<u64>) -> anyhow::Result<u32> {
        let mut fq_cq = self.inner.lock().unwrap();
        let mut writer = fq_cq.0.fill(desc_list.len() as u32);
        let mut filled = 0;
        while let Some(addr) = desc_list.pop_front() {
            if writer.insert_once(addr) {
                filled += 1;
            } else {
                failed.push_back(addr);
            }
        }
        writer.commit();
        Ok(filled)
    }
    pub fn complete(&mut self, total_queues: u32, complete_address_list: &mut HashMap<u64, Arc<Mutex<VecDeque<u64>>>>) -> anyhow::Result<u32> {
        let mut fq_cq = self.inner.lock().unwrap();
        let mut completed = 0;
        let available = fq_cq.0.available();
        let mut reader = fq_cq.0.complete(available);
        while let Some(addr) = reader.read() {
            let addr = addr - HEADROOM as u64;
            let interval = BUFFER_SIZE / total_queues;
            let queue_idx = addr / interval as u64;
            let queue_idx = queue_idx.min(total_queues as u64 - 1);
            complete_address_list.get(&queue_idx).unwrap().lock().unwrap().push_back(addr);
            completed += 1;
        }
        reader.release();
        Ok(completed)
    }
    pub fn pending(&mut self) -> anyhow::Result<u32> {
        let fq_cq = self.inner.lock().unwrap();
        let pending = fq_cq.0.pending();
        Ok(pending)
    }
}

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
    mac_table: BpfHashMap<MapData, [u8;6], u32>,
}

impl AfXdp{
    pub fn new(
        interface_list: HashMap<u32, Interface>,
        xsk_map: XskMap<MapData>,
        interface_queue_table: BpfHashMap<MapData, InterfaceQueue, u32>,
        mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
    ) -> Self{
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
            mac_table,
        }
    }
    pub async fn run<'a>(&self, handler: impl PacketHandler + 'static + Send + Sync + Clone) -> anyhow::Result<()>{
        let mut queue_manager = QueueManager::new(
            self.interface_list.clone(), 
            self.xsk_map.clone(), 
            self.interface_queue_table.clone(),
            self.mac_table.clone(),
        );
        queue_manager.run(handler).await.unwrap();
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
    mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
}

impl QueueManager{
    fn new(
        interface_list: HashMap<u32, Interface>,
        xsk_map: Arc<Mutex<XskMap<MapData>>>,
        interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
        mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
    ) -> Self{
        QueueManager{
            xsk_map,
            interface_queue_table,
            interface_list,
            mac_table
        }
    }
    pub async fn run(&mut self, handler: impl PacketHandler + 'static + Send + Sync + Clone) -> anyhow::Result<()>{
        let mut queue_list = Vec::new();
        let mut ring_tx_map = HashMap::new();
        let mut complete_counter_map = HashMap::new();
        let mut complete_address_list: HashMap<u64, Arc<Mutex<VecDeque<u64>>>> = HashMap::new();
        let total_queues: u32 = self.interface_list.iter().map(|(_k,v)| v.queues).sum();

        //let ring_rx_map = HashMap::new();
        let mut jh_list = Vec::new();
        {            
            let mem = NonNull::new(MEM.0.get() as *mut [u8]).unwrap();
            let mut umem_config = UmemConfig::default();
            umem_config.frame_size = FRAME_SIZE;
            let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();

            let per_queue_frames = umem.len_frames()/total_queues;
            let rx_size = per_queue_frames/2;
            let tx_size = per_queue_frames;
            let fq_size = per_queue_frames;
            let threshold = per_queue_frames/THRESOLD_FACTOR;
            info!("total queues: {}", total_queues);
            info!("total frames: {}", umem.len_frames());
            info!("per queue frames: {}", per_queue_frames);
            info!("rx size: {}", rx_size);
            info!("tx size: {}", tx_size);
            info!("fq size: {}", fq_size);
            info!("threshold: {}", threshold);
            let mut rx_tx_config = SocketConfig {
                rx_size: NonZeroU32::new(rx_size),
                tx_size: NonZeroU32::new(tx_size),
                bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_SHARED_UMEM,
            };
            let mut idx = 0;
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
                    let queue_frame_start = per_queue_frames * idx;
                    let queue_frame_end = queue_frame_start + per_queue_frames;
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
                        frame_buffer.insert(recv_frame.offset, recv_buf);
                    }
                    {
                        info!("filling fq_cq with {} frames, fb length: {}", fq_size, frame_buffer.len());
                        let mut writer = fq_cq.fill(fq_size);
                        writer.insert(frame_buffer.iter().map(|(addr, _d)| addr.clone()));
                        writer.commit();
                    }

                    let interface_queue = InterfaceQueue::new(interface.ifidx, queue_id);
                    interface_queue_table.insert(interface_queue, idx, 0).unwrap();
                    xsk_map.set(idx, ring_rx.as_raw_fd(), 0).unwrap();
                    info!("queue: {},{} pending {}", interface.ifidx, queue_id, fq_cq.pending());
                    info!("queue: {},{} available {}", interface.ifidx, queue_id, fq_cq.available());
                    let complete_list = Arc::new(Mutex::new(VecDeque::new()));
                    let queue = Queue::new(
                        (queue_frame_start  * FRAME_SIZE) as u64,
                        (queue_frame_end * FRAME_SIZE) as u64,
                        queue_id,
                        interface.ifidx,
                        self.interface_list.clone(),
                        Arc::new(RwLock::new(MyDeviceQueue(fq_cq))),
                        threshold,
                        total_queues,
                        complete_list.clone(),
                    );
                    
                    ring_tx_map.insert((interface.ifidx, queue_id), Arc::new(Mutex::new(ring_tx)));
                    complete_counter_map.insert(idx as u64, 0);
                    complete_address_list.insert(idx as u64, complete_list);
                    queue_list.push((queue, ring_rx, frame_buffer));
                    idx += 1;
                }
            }

        }

        let complete_counter_map = Arc::new(Mutex::new(complete_counter_map));
        for (mut queue, ring_rx, frame_buffer) in queue_list{
            info!("starting queue: {},{}", queue.ifidx, queue.queue_id);
            info!("frame buffer len: {}", frame_buffer.len());
            info!("start: {} end: {}", queue.buf_start, queue.buf_end);
            let ring_tx_map = ring_tx_map.clone();
            queue.complete_counter_map = complete_counter_map.clone();
            queue.complete_address_list = complete_address_list.clone();
            let mac_table = self.mac_table.clone();
            let handler_clone = handler.clone(); // Clone the handler variable
            let jh = tokio::spawn(async move{
                queue.run(frame_buffer, ring_rx, ring_tx_map, handler_clone, mac_table).await.unwrap();
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
    fq_cq: Arc<RwLock<MyDeviceQueue>>,
    thresholds: u32,
    queue_id: u32,
    ifidx: u32,
    interface_list: HashMap<u32, Interface>,
    complete_counter_map: Arc<Mutex<HashMap<u64, u64>>>,
    complete_address_list: HashMap<u64, Arc<Mutex<VecDeque<u64>>>>,
    complete_list: Arc<Mutex<VecDeque<u64>>>,
}

impl Queue{
    fn new(
        buf_start: u64,
        buf_end: u64,
        queue_id: u32,
        ifidx: u32,
        interface_list: HashMap<u32, Interface>,
        fq_cq: Arc<RwLock<MyDeviceQueue>>,
        thresholds: u32,
        totol_queues: u32,
        complete_list: Arc<Mutex<VecDeque<u64>>>,
    ) -> Self{
        Queue{
            buf_start,
            buf_end,
            totol_queues,
            thresholds,
            queue_id,
            fq_cq,
            ifidx,
            interface_list,
            complete_counter_map: Arc::new(Mutex::new(HashMap::new())),
            complete_address_list: HashMap::new(),
            complete_list,
        }
    }

    pub async fn run(
        &self,
        mut frame_buffer: HashMap<u64, &'static mut [u8]>,
        mut ring_rx: RingRx,
        ring_tx_map: HashMap<(u32,u32), Arc<Mutex<RingTx>>>,
        mut handler: impl PacketHandler + 'static + Send + Sync + Clone,
        mac_table: Arc<Mutex<BpfHashMap<MapData, [u8;6], u32>>>,
    ) -> anyhow::Result<()> {
        let mut jh_list = Vec::new();

        let queue_id = self.queue_id;
        let ifidx = self.ifidx;
        let queue_id_ifidx = format!{"{}:{}", ifidx, queue_id};
        let thresholds = self.thresholds;
        let total_queues_clone = self.totol_queues;
        let interface_list = self.interface_list.clone();
        let fq_cq_clone = self.fq_cq.clone();
        let mut complete_address_list_clone = self.complete_address_list.clone();
        
        let jh = tokio::spawn(async move{
            let mut collect_interval = tokio::time::interval(Duration::from_nanos(COMPLETE_INTERVAL));
            loop{
                collect_interval.tick().await;
                let mut fq_cq = fq_cq_clone.write().await;
                let _completed = complete(&mut fq_cq, total_queues_clone, &mut complete_address_list_clone).unwrap();
            }
        });
        jh_list.push(jh);
        

        let fq_cq_clone = self.fq_cq.clone();
        let complete_list = self.complete_list.clone();

        let jh = tokio::spawn(async move{
            let mut receive_interval = tokio::time::interval(Duration::from_nanos(RX_INTERVAL));
            //let mut pending_now = tokio::time::Instant::now();
            let mut receive_counter = 0;
            let mut total_sent_counter = 0;
            let mut total_receive_counter = 0;
            let mut total_fill_list_counter = 0;
            let mut total_fill_counter = 0;
            let mut send_map: HashMap<(u32, u32), VecDeque<XdpDesc>> = HashMap::new();
            for interface in interface_list.values(){
                for queue_id in 0..interface.queues{
                    let desc_list: VecDeque<XdpDesc>  = VecDeque::new();
                    send_map.insert((interface.ifidx, queue_id), desc_list);
                }
            }
            let mut fill_list = VecDeque::new();
            let mut idle_timer = tokio::time::Instant::now();
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            let mac_table = mac_table.clone();
            loop{
                receive_interval.tick().await;

                let mut fq_cq = fq_cq_clone.write().await;
                if receive_counter > thresholds{
                    let mut complete_fill_list: VecDeque<u64> = complete_list.lock().unwrap().drain(0..).collect();
                    total_fill_list_counter += complete_fill_list.len();
                    loop{
                        let mut failed_list = VecDeque::new();
                        
                        let filled_temp = fill(&mut fq_cq, &mut complete_fill_list, &mut failed_list).unwrap();
                        total_fill_counter += filled_temp;
                        if failed_list.len() == 0{
                            break;
                        }
                        complete_fill_list = failed_list;
                    }
                    drop(complete_fill_list);
                    receive_counter = 0;
                }
        
                let mut receiver = ring_rx.receive(BATCH_SIZE);
                let mut batch_counter = 0;

                while let Some(desc) = receiver.read() {
                    idle_timer = tokio::time::Instant::now();
                    receive_counter += 1;
                    batch_counter += 1;
                    total_receive_counter += 1;
                    let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                    let offset = desc.addr - buf_idx;


                    if let Some(buf) = frame_buffer.get_mut(&buf_idx) {
                        let mut buf = &mut buf.as_mut()[offset as usize..];
                        if let Some(eth_packet) = MutableEthernetPacket::new(&mut buf){
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
                                                    send_map.get_mut(&(interface.ifidx, queue_id)).unwrap().push_back(desc);
                                                }  
                                            },
                                            _ => {},
                                        }
                                    } else {
                                        fill_list.push_back(desc.addr);
                                        error!("failed to parse arp packet");
                                    }
                                },
                                
                                EtherTypes::Ipv4 => {
                                    let dst_mac: [u8;6] = eth_packet.get_destination().into();
                                    let dst_ifidx = if let Some(dst_ifidx) = local_mac_table.get(&dst_mac){
                                        *dst_ifidx
                                    } else {
                                        if let Ok(dst_ifidx) = mac_table.lock().unwrap().get(&dst_mac.into(),0){
                                            local_mac_table.insert(dst_mac, dst_ifidx);
                                            dst_ifidx
                                        } else {
                                            fill_list.push_back(desc.addr);
                                            error!("failed to get dst ifidx");
                                            continue;
                                        }
                                    };
                                    send_map.get_mut(&(dst_ifidx, queue_id)).unwrap().push_back(desc);
                                },
                        
                                _ => {
                                    fill_list.push_back(desc.addr);
                                    //error!("failed to parse packet, not arp or ipv4 {:#?}", eth_packet);
                                }
                            }
                        } else {
                            fill_list.push_back(desc.addr);
                            error!("failed to parse ethernet packet");
                        }
                    } else {
                        fill_list.push_back(desc.addr);
                        error!("failed to get buffer for address {}", desc.addr);
                    }

                    /*
                    if let Some(buf) = frame_buffer.get_mut(&buf_idx) {
                        let mut buf = &mut buf.as_mut()[offset as usize..];
                        //let now = tokio::time::Instant::now();
                        if let Some(list) = handler.handle_packet(&mut buf, ifidx, queue_id).await{
                            //info!("took: {} micros", now.elapsed().as_micros());
                            for (ifidx, queue_id) in list{
                                send_map.get_mut(&(ifidx, queue_id)).unwrap().push_back(desc);
                            }
                        } else {
                            fill_list.push_back(desc.addr);
                        }
                    } else {
                        fill_list.push_back(desc.addr);
                        error!("failed to get buffer for address {}", desc.addr);
                    }
                    */
                }

                if idle_timer.elapsed() > tokio::time::Duration::from_secs(2){
                    let mut complete_fill_list: VecDeque<u64> = complete_list.lock().unwrap().drain(0..).collect();
                    total_fill_list_counter += complete_fill_list.len();
                    loop{
                        let mut failed_list = VecDeque::new();
                        let filled_temp = fill(&mut fq_cq, &mut complete_fill_list, &mut failed_list).unwrap();
                        //filled += filled_temp;
                        total_fill_counter += filled_temp;
                        if failed_list.len() == 0{
                            break;
                        }
                        complete_fill_list = failed_list;
                    }
                    drop(complete_fill_list);
                }


                if batch_counter > 0{
                    //info!("{} batch received: {}, total {}", queue_id_ifidx, batch_counter, total_receive_counter);
                }

                receiver.release();

                
                for ((ifidx, queue_id), mut desc_list) in &mut send_map{
                    if desc_list.len() == 0{
                        continue;
                    }
                    if let Some(ring_tx) = ring_tx_map.get(&(*ifidx, *queue_id)){
                        loop {
                            let mut failed_list = VecDeque::new();
                            let sent = send(&mut desc_list, &mut failed_list, ring_tx).unwrap();
                            total_sent_counter += sent;
                            if failed_list.len() == 0{
                                break;
                            }
                            *desc_list = failed_list;
                        }
                    } else {
                        panic!("failed to get ring_tx for ifidx: {}, queue_id: {}", ifidx, queue_id);
                    }
                }

                let mut filled = 0;

                let now = tokio::time::Instant::now();
                if fill_list.len() > thresholds as usize{ 
                    loop{
                        let mut failed_list = VecDeque::new();
                        let filled_temp = fill(&mut fq_cq, &mut fill_list, &mut failed_list).unwrap();
                        if failed_list.len() == 0{
                            break;
                        }
                        filled += filled_temp;
                        total_fill_counter += filled_temp;
                        fill_list = failed_list;
                    }
                }
                let elapsed = now.elapsed();
                if filled > 0 {
                    info!("{} filled: {}, batch: {}, total: {} in {} micros",queue_id_ifidx, filled, batch_counter, total_fill_counter, elapsed.as_micros());
                }

                let pending_cnt =  pending(&mut fq_cq).unwrap();
                if pending_cnt <= thresholds{
                    
                    
                    let mut complete_fill_list: VecDeque<u64> = complete_list.lock().unwrap().drain(0..).collect();
                    //error!("{} 2 pending: {} threshold: {}, complete_fill_list: {}", queue_id_ifidx, pending_cnt, thresholds, complete_fill_list.len());
                    total_fill_list_counter += complete_fill_list.len();
                    loop{
                        let mut failed_list = VecDeque::new();
                        let filled_temp = fill(&mut fq_cq, &mut complete_fill_list, &mut failed_list).unwrap();
                        //filled += filled_temp;
                        total_fill_counter += filled_temp;
                        if failed_list.len() == 0{
                            break;
                        }
                        complete_fill_list = failed_list;
                    }
                    drop(complete_fill_list);
                }

            }
        });
        jh_list.push(jh);
        futures::future::join_all(jh_list).await;
        Ok(())
    }
    
}

fn send(descriptors: &mut VecDeque<XdpDesc>, failed: &mut VecDeque<XdpDesc>, ring_tx: &Arc<Mutex<RingTx>>) -> anyhow::Result<u32>{
    let mut ring_tx = ring_tx.lock().unwrap();
    let mut sent = 0;
    {
        let mut writer = ring_tx.transmit(descriptors.len() as u32);
        while let Some(desc) = descriptors.pop_front(){
            if writer.insert_once(desc){
                sent += 1;
            } else {
                failed.push_back(desc);
            }
        }
        writer.commit();
    }
    if ring_tx.needs_wakeup(){
        ring_tx.wake();
    }
    //info!("{} sent: {}",queue_id_ifidx, descriptors.len());
    Ok(sent)
}

fn complete(fq_cq: &mut RwLockWriteGuard<'_, MyDeviceQueue>, total_queues: u32, complete_address_list: &mut HashMap<u64, Arc<Mutex<VecDeque<u64>>>>) -> anyhow::Result<u32>{
    //let mut fq_cq = fq_cq.write().await;
    let mut completed = 0;
    let available = fq_cq.0.available();
    
    let mut reader = fq_cq.0.complete(available);
    
    while let Some(addr) = reader.read(){
        let addr = addr - HEADROOM as u64;
        //info!("{} Read descriptor with address: {}",queue_id_ifidx_clone, desc);
        let interval = BUFFER_SIZE/total_queues;
        let queue_idx = addr/interval as u64;
        let queue_idx = queue_idx.min(total_queues as u64-1);
        complete_address_list.get(&queue_idx).unwrap().lock().unwrap().push_back(addr);        
        completed += 1;
    }
    reader.release();
    Ok(completed)
}

fn fill(fq_cq: &mut RwLockWriteGuard<'_, MyDeviceQueue>, desc_list: &mut VecDeque<u64>, failed: &mut VecDeque<u64>) -> anyhow::Result<u32>{
    let mut writer = fq_cq.0.fill(desc_list.len() as u32);
    let mut filled = 0;
    while let Some(addr) = desc_list.pop_front(){
        if writer.insert_once(addr){
            filled += 1;
        } else {
            failed.push_back(addr);
        }
    }

    writer.commit();
    Ok(filled)
}

fn pending(fq_cq: &mut RwLockWriteGuard<'_, MyDeviceQueue>) -> anyhow::Result<u32>{
    let pending = fq_cq.0.pending();
    Ok(pending)
}

#[async_trait]
pub trait PacketHandler: Send + Sync + Clone{
    async fn handle_packet(&mut self, buf: &mut [u8], ifidx: u32, queue_id: u32) -> Option<Vec<(u32, u32)>>;
}