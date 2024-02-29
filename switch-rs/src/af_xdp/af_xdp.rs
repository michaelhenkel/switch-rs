use core::{mem::MaybeUninit, num::NonZeroU32, ptr::NonNull};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use switch_rs_common::InterfaceQueue;
use tokio::sync::RwLock;
use xdpilone::xdp::XdpDesc;
use aya::maps::{HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::{error, info};
use super::interface::interface::Interface;

#[repr(align(4096))]
struct PacketMap(MaybeUninit<[u8; 1 << 20]>);

const BLA: u32 = 1 << 20;

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
                let (tx, rx) = tokio::sync::mpsc::channel(100);
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
    pub async fn run(&mut self, recv_tx: tokio::sync::mpsc::UnboundedSender<(u32, Arc<RwLock<[u8]>>)>) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>>{
        let mut rx_map = self.rx_map.clone();
        let interface_list = self.interface_list.clone();

        let mut jh_list = Vec::new();

        let mut idx = 0;

        for (ifidx, interface) in interface_list{
            let recv_tx = recv_tx.clone();
            let xsk_map = self.xsk_map.clone();
            let interface_queue_table = self.interface_queue_table.clone();
            let rx = rx_map.remove(&ifidx).unwrap();
            
            let jh = tokio::spawn(async move{
                let _ = interface_runner(interface.clone(), xsk_map, interface_queue_table, rx.clone(), recv_tx, idx).await;
                
            });
            jh_list.push(jh);
            idx += 1;

        }
        Ok(jh_list)
    }
}

pub async fn interface_runner(
    interface: Interface,
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
    mut rx: HashMap<u32,Arc<RwLock<tokio::sync::mpsc::Receiver<Arc<RwLock<[u8]>>>>>>,
    recv_tx: tokio::sync::mpsc::UnboundedSender<(u32,Arc<RwLock<[u8]>>)>,
    mut idx: u32,
) -> anyhow::Result<()>{

    const FRAMES: u32 = 64;
    const FILL_THRESHOLD: u32 = 1 << 5;
    const COMPLETE_THRESHOLD: u32 = 1 << 5;
    const FRAME_SIZE: u32 = 1 << 12;
    const HEADROOM: u32 = 1 << 8;
    const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;
    let mut jh_list = Vec::new();
    

    //const BLA: u32 = 1 << 14;

    idx = idx * interface.queues;

    for queue_id in 0..interface.queues{
        let mut recv_packet_counter = 0;
        let mut send_packet_counter = 0;
        let mut total_recv_packet_counter = 0;
        let mut total_send_packet_counter = 0;
        let (mut fq_cq, mut ring_rx, mut ring_tx,mut recv_frame_buffer_list,  mut send_frame_buffer_list) ={
            let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
            let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
            let mut umem_config = UmemConfig::default();
            umem_config.frame_size = FRAME_SIZE;
            let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();
            let info = ifinfo(&interface.name, Some(queue_id)).unwrap();
            let sock = Socket::with_shared(&info, &umem).unwrap();
            let mut fq_cq = umem.fq_cq(&sock).unwrap();
            let rxtx = umem
            .rx_tx(
                &sock,
                &SocketConfig {
                    rx_size: NonZeroU32::new(1 << 11),
                    tx_size: NonZeroU32::new(1 << 14),
                    bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
                },
            ).unwrap();

            let ring_tx = rxtx.map_tx().unwrap();
            let ring_rx = rxtx.map_rx().unwrap();
            umem.bind(&rxtx).unwrap();
            let interface_queue = InterfaceQueue::new(interface.ifidx, queue_id);
            let mut interface_queue_table = interface_queue_table.lock().unwrap();
            interface_queue_table.insert(interface_queue, idx, 0).unwrap();
            let mut xsk_map = xsk_map.lock().unwrap();
            xsk_map.set(idx, fq_cq.as_raw_fd(), 0).unwrap();
 

            let mut recv_frame_buffer_list = HashMap::new();
            let mut buf_idx_counter = 0;
            info!("umem frames: {}", umem.len_frames());
            for i in 0..1 << 8{
                let mut recv_frame = match umem.frame(BufIdx(i)){
                    Some(recv_frame) => recv_frame,
                    None => {
                        error!("failed to get frame from umem: {}", i);
                        break;
                    }
                };
                let recv_buf = unsafe { recv_frame.addr.as_mut() };
                recv_frame_buffer_list.insert(recv_frame.offset, recv_buf);
                buf_idx_counter += 1;
            }

            {
                let mut writer = fq_cq.fill(1 << 14);
                writer.insert(recv_frame_buffer_list.iter().map(|(addr, _d)| addr.clone()));
                writer.commit();
            }

            let mut send_frame_buffer_list = Vec::new();
            for i in 0..1 << 8{
                //idx = i + buf_idx_counter;
                let mut send_frame = umem.frame(BufIdx(i)).unwrap();
                let send_buf = unsafe { send_frame.addr.as_mut() };
                let send_desc = XdpDesc{
                    addr: send_frame.offset,
                    len: 0,
                    options: 0,
                };
                send_frame_buffer_list.push((send_buf, send_desc));
            }

            (fq_cq, ring_rx, ring_tx ,recv_frame_buffer_list, send_frame_buffer_list)
        };

        let rx = rx.remove(&queue_id).unwrap();
        let mut rcv_interval = tokio::time::interval(Duration::from_nanos(10));
        let recv_tx = recv_tx.clone();
        let jh = tokio::spawn(async move {
            let mut rx = rx.write().await;
            let mut buffer = Vec::with_capacity(FRAMES as usize);
            loop{
                let sent_now: u32; 
                tokio::select! {
                    n = rx.recv_many(&mut buffer, FRAMES as usize) => {
                        let mut desc_list = Vec::with_capacity(n as usize);
                        for i in 0..n as usize{
                            let msg = &buffer[i];
                            let msg = msg.write().await;
                            let (sb, sd) = &mut send_frame_buffer_list[i];
                            sb[..msg.len()].copy_from_slice(&msg); 
                            sd.len = msg.len() as u32;
                            desc_list.push(*sd);
                        }
                        {
                            let mut writer = ring_tx.transmit(n as u32);
                            sent_now = writer.insert(desc_list.iter().map(|desc| desc.clone()));
                            writer.commit();
                            total_send_packet_counter += sent_now;
                            //info!("interface {}/{} sent packet 4", interface.ifidx, queue_id);
                            send_packet_counter += sent_now;
                        }
                        info!("total sent packet: {}", total_send_packet_counter);
                        
                        buffer.clear();
                        if ring_tx.needs_wakeup(){
                            ring_tx.wake();
                        }
                        {   
                            if send_packet_counter > COMPLETE_THRESHOLD{
                                let mut reader = fq_cq.complete(send_packet_counter);
                                while reader.read().is_some() {
                                    //comp_temp += 1;
                                }
                                //comp_now = comp_temp;
                                reader.release();
                            }
                        }
                    },
                    _ = rcv_interval.tick() => {
                        let mut receiver = ring_rx.receive(FRAMES);
                        if receiver.capacity() > 0 {
                            //info!("interface {}/{} received packet 2", interface.ifidx, queue_id);
                            while let Some(desc) = receiver.read(){
                                let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                                let offset = desc.addr - buf_idx;
                                if let Some(buf) = recv_frame_buffer_list.get_mut(&buf_idx){
                                    let d = &buf.as_ref()[offset as usize..];
                                    let b: [u8;PAYLOAD_SIZE as usize] = d.try_into().unwrap();
                                    recv_tx.send((interface.ifidx, Arc::new(RwLock::new(b)))).unwrap();
                                    recv_packet_counter += 1;
                                    total_recv_packet_counter += 1;
                                }
                            }
                            receiver.release();
                            {
                                if recv_packet_counter > FILL_THRESHOLD{
                                    let mut writer = fq_cq.fill(recv_packet_counter);
                                    writer.insert(recv_frame_buffer_list.iter().map(|(k,_v)| k.clone()));
                                    writer.commit();
                                    recv_packet_counter = 0;
                                }
                            }
                            info!("total received packet: {}", total_recv_packet_counter);
                        } else {
                            fq_cq.wake();
                        }
                        //tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    },                    
                }
            }
        });
        jh_list.push(jh);
        idx += 1;
    }
    
    futures::future::join_all(jh_list).await;

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