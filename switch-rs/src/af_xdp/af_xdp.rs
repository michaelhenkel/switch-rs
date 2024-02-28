use core::{mem::MaybeUninit, num::NonZeroU32, ptr::NonNull};
use std::{collections::{HashMap, HashSet}, sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use switch_rs_common::InterfaceQueue;
use tokio::sync::RwLock;
use xdpilone::xdp::XdpDesc;
use aya::maps::{HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::info;
use super::interface::interface::Interface;

#[repr(align(4096))]
struct PacketMap(MaybeUninit<[u8; 1 << 20]>);

#[derive(Clone)]
pub struct AfXdpClient{
    tx_map: HashMap<u32, HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

impl AfXdpClient{
    pub fn new(tx_map: HashMap<u32, HashMap<u32,tokio::sync::mpsc::Sender<Vec<u8>>>>) -> Self{
        AfXdpClient{
            tx_map,
        }
    }
    pub async fn send(&mut self, ifidx: u32, queue_id: u32, buf: Vec<u8>) -> anyhow::Result<()>{
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
    rx_map: HashMap<u32, HashMap<u32,Arc<RwLock<tokio::sync::mpsc::Receiver<Vec<u8>>>>>>,
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
    pub async fn run(&mut self, recv_tx: tokio::sync::mpsc::UnboundedSender<(u32, Vec<u8>)>) -> anyhow::Result<Vec<tokio::task::JoinHandle<()>>>{
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
    mut rx: HashMap<u32,Arc<RwLock<tokio::sync::mpsc::Receiver<Vec<u8>>>>>,
    recv_tx: tokio::sync::mpsc::UnboundedSender<(u32,Vec<u8>)>,
    mut idx: u32,
) -> anyhow::Result<()>{

    let frame_number = 2;
    let mut jh_list = Vec::new();
    

    //const BLA: u32 = 1 << 14;

    idx = idx * interface.queues;

    for queue_id in 0..interface.queues{
        let mut stall_count = 0;
        const WAKE_THRESHOLD: u32 = 1 << 4;
        let mut stall_threshold = WAKE_THRESHOLD;
        let (mut fq_cq, mut ring_rx, mut ring_tx,mut recv_frame_buffer_list,  mut send_frame_buffer_list) ={
            let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
            let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
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
            /* 
            let mut frame_list = Vec::new();
            for i in 0..frame_number{
                frame_list.push(umem.frame(BufIdx(i)).unwrap());
            }
            */

            let mut recv_frame_buffer_list = HashMap::new();
            let mut buf_idx_counter = 0;
            for i in 0..frame_number{
                let mut recv_frame = umem.frame(BufIdx(i+1)).unwrap();
                let recv_buf = unsafe { recv_frame.addr.as_mut() };
                info!("recv frame addr: {:?}", recv_frame.addr);
                info!("frane number: {}", i);
                info!("recv buf len: {}", recv_buf.len());
                info!("recv frame offset: {}", recv_frame.offset);
                recv_frame_buffer_list.insert(recv_frame.offset, recv_buf);
                
                buf_idx_counter += 1;
                /*
                let recv_desc = XdpDesc{
                    addr: recv_frame.offset,
                    len: 0,
                    options: 0,
                };
                recv_frame_buffer_list.push((recv_buf, recv_desc));
                buf_idx_counter += 1;
                */
            }
            //info!("recv buf list: {:?}", recv_frame_buffer_list);

            /* 
            let mut frame = umem.frame(BufIdx(0)).unwrap();
            info!("available frames: {}", umem.len_frames());
            */
            for (k,_) in &recv_frame_buffer_list{
                info!("recv frame buffer list: {}", k);
            }

            {
                let mut writer = fq_cq.fill(frame_number);
                writer.insert(recv_frame_buffer_list.iter().map(|(addr, _d)| addr.clone()));
                //writer.insert_once(frame.offset);
                writer.commit();
            }

            //let recv_buf = unsafe { frame.addr.as_mut() };

            let mut send_frame_buffer_list = Vec::new();
            for i in 0..frame_number{
                idx = i + buf_idx_counter;
                info!("send buf idx: {}", idx);
                let mut send_frame = umem.frame(BufIdx(idx)).unwrap();
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
        let mut complete_interval = tokio::time::interval(Duration::from_millis(1));
        let mut rcv_interval = tokio::time::interval(Duration::from_nanos(10));
        let recv_tx = recv_tx.clone();
        let batch: u32 = 1 << 10;
        let mut sent = 0;
        let mut completed = 0;
        let jh = tokio::spawn(async move {
            let mut rx = rx.write().await;
            let mut buffer = Vec::with_capacity(frame_number as usize);
            loop{
                let sent_now: u32; 
                tokio::select! {
                    n = rx.recv_many(&mut buffer, frame_number as usize) => {
                        let mut desc_list = Vec::with_capacity(n as usize);
                        for i in 0..n as usize{
                            let msg = &buffer[i];
                            
                            let s = msg.as_slice();
                            info!("SEND received {} packets with len {} for transmission", n, s.len());
                            let (sb, sd) = &mut send_frame_buffer_list[i];
                            sb[..s.len()].copy_from_slice(s); 
                            sd.len = s.len() as u32;
                            desc_list.push(*sd);
                        }
                        {
                            let mut writer = ring_tx.transmit(n as u32);
                            sent_now = writer.insert(desc_list.iter().map(|desc| desc.clone()));
                            info!("SEND sent {} packets", sent_now);
                            writer.commit();
                        } 
                        buffer.clear();
                        if ring_tx.needs_wakeup(){
                            info!("SEND waking up ring_tx");
                            ring_tx.wake();
                        }
                        let comp_now: u32;   
                        {
                            let mut reader = fq_cq.complete(frame_number);
                            let mut comp_temp = 0;
                            while reader.read().is_some() {
                                comp_temp += 1;
                            }
                            comp_now = comp_temp;
                            reader.release();
                            info!("SEND completed {} packets", comp_now);
                        }
                    },
                    _ = rcv_interval.tick() => {
                        let mut packets = 0;
                        let mut receiver = ring_rx.receive(frame_number);
                        if receiver.capacity() > 0 {
                            info!("RCV receiver capacity 1: {}",receiver.capacity());
                            let mut desc_list = Vec::with_capacity(frame_number as usize);
                            while let Some(desc) = receiver.read(){
                                desc_list.push(desc);
                                packets += 1;
                                /* 
                                info!("RCV received packet on interface {} queue {}", interface.ifidx, queue_id);
                                let buf = &recv_buf.as_ref()[desc.addr as usize..(desc.addr as usize + desc.len as usize)];
                                let data = buf.to_vec();
                                receiver.release();
                                {
                                    let mut writer = fq_cq.fill(frame_number);
                                    writer.insert_once(desc.addr);
                                    writer.commit();
                                }
                                recv_tx.send((interface.ifidx, data)).unwrap();
                                */
                            }
                            receiver.release();
                            info!("pushed {} descs", desc_list.len());
                            let mut c = 1;
                            //info!("recv frame buffer list: {:?}", recv_frame_buffer_list);
                            for recv_desc in &desc_list{
                                info!("recv desc_addr: {}", recv_desc.addr);
                                let buf_idx = (recv_desc.addr / 4096) * 4096;
                                let offset = recv_desc.addr - buf_idx;
                                info!("buf_idx: {}", buf_idx);
                                info!("offset: {}", offset);
                                
                                if let Some(buf) = recv_frame_buffer_list.get_mut(&buf_idx){
                                    info!("read data from buffer");
                                    let d = &buf.as_ref()[offset as usize..];
                                    let data = d.to_vec();
                                    info!("data len: {}", data.len());
                                    recv_tx.send((interface.ifidx, data)).unwrap();
                                    info!("sent {} packet to recv_tx", c);
                                    c += 1;
                                } else {
                                    info!("buffer not found: {:?}", recv_frame_buffer_list);
                                }
                            }
                            {
                                info!("filling fq_cq with {} packets", packets);
                                let mut writer = fq_cq.fill(packets);
                                writer.insert(desc_list.iter().map(|desc| desc.addr));
                                writer.commit();
                            }

                        } else {
                            fq_cq.wake();
                        }
                        if packets > 0 {
                            info!("RCV received {} packets", packets);
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