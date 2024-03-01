use core::{mem::MaybeUninit, num::NonZeroU32, ptr::NonNull};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};
use anyhow::anyhow;
use pnet::{datalink::EtherType, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, MutableEthernetPacket}, Packet}};
use switch_rs_common::InterfaceQueue;
use tokio::sync::{mpsc::error, RwLock};
use xdpilone::{xdp::XdpDesc, DeviceQueue, RingRx, RingTx};
use aya::maps::{queue, HashMap as BpfHashMap, MapData, XskMap};
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};
use log::{error, info};
use crate::af_xdp::interface::interface;

use super::interface::interface::Interface;


const BUFFER_SIZE: u32 = 1 << 20;
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

        /*
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
        */
        Ok(jh_list)
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
        tx: HashMap<(u32, u32), Tx<'a>>,
        fq_cq: HashMap<(u32, u32), Dq>,
    }

    struct Rx<'a>{
        ring_rx: RingRx,
        recv_frame_buffer_list: HashMap<u64, &'a mut [u8]>,
        interface: Interface,
        thresholds: u32,
    }

    struct Tx<'a>{
        ring_tx: RingTx,
        send_frame_buffer_list: HashMap<u64, &'a mut [u8]>,
        rx: tokio::sync::mpsc::Receiver<XdpDesc>,
        thresholds: u32,
    }

    struct Dq{
        fq_cq: DeviceQueue,
        rx: tokio::sync::mpsc::Receiver<FillComplete>,
    }

    let mut tx_map = HashMap::new();
    let mut dq_map = HashMap::new();

    let mut recv_packet_counter = 0;
    let mut send_packet_counter = 0;
    let mut total_recv_packet_counter = 0;
    let mut total_send_packet_counter = 0;
    let mut total_fill_count = 0;
    let mut total_comp_count = 0;

    let mac_table_mutex = Arc::new(RwLock::new(mac_table));

    let res = {
        let alloc = Box::new(PacketMap(MaybeUninit::uninit()));
        let mem = NonNull::new(Box::leak(alloc).0.as_mut_ptr()).unwrap();
        let mut umem_config = UmemConfig::default();
        umem_config.frame_size = FRAME_SIZE;
        let umem = unsafe { Umem::new(UmemConfig::default(), mem) }.unwrap();
        let mut interface_queue_res = InterfaceQueueRes{
            rx: HashMap::new(),
            tx: HashMap::new(),
            fq_cq: HashMap::new(),
        };

        info!("interfaces: {:?}", interfaces);
        let mut interface_list: Vec<(Interface, u32)> = interfaces.iter().map(|(_k,v)| (v.clone(), v.queues)).collect();
        interface_list.sort_by_key(|(v,_)| v.ifidx);
        info!("interface list: {:?}", interface_list);
        let rx_tx_config = SocketConfig {
            rx_size: NonZeroU32::new(1 << 11),
            tx_size: NonZeroU32::new(1 << 14),
            //bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_SHARED_UMEM,
            bind_flags: 0,
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

                let (send_tx, send_rx) = tokio::sync::mpsc::channel(10000);
                let (dq_tx, dq_rx) = tokio::sync::mpsc::channel(10000);
                let rx = Rx{
                    ring_rx,
                    recv_frame_buffer_list,
                    thresholds,
                    interface: interface.clone(),
                };
                let tx = Tx{
                    ring_tx,
                    send_frame_buffer_list,
                    rx: send_rx,
                    thresholds,
                };
                let dq = Dq{
                    fq_cq,
                    rx: dq_rx,
                };
                interface_queue_res.rx.insert((interface.ifidx, queue_id), rx);
                interface_queue_res.tx.insert((interface.ifidx, queue_id), tx);
                interface_queue_res.fq_cq.insert((interface.ifidx, queue_id), dq);
                tx_map.insert((interface.ifidx, queue_id), send_tx);
                dq_map.insert((interface.ifidx, queue_id), dq_tx);
            }
        }
        interface_queue_res
    };


    
    let mut jh_list = Vec::new();

    for ((ifidx, queue_id), mut rx) in res.rx{
        let tx_map = tx_map.clone();
        let dq_map = dq_map.clone();
        let interface_list = interfaces.clone();
        let mac_table_mutex = mac_table_mutex.clone();
        let jh = tokio::spawn(async move{
            let mac_table_mutex = mac_table_mutex.clone();
            let mut rcv_interval = tokio::time::interval(Duration::from_nanos(10));
            let prefix = format!("RECV {}:{}", ifidx, queue_id);
            let mut desc_list = Vec::new();
            let mut local_mac_table: HashMap<[u8;6], u32> = HashMap::new();
            loop{
                rcv_interval.tick().await;
                let mut receiver = rx.ring_rx.receive(FRAMES);
                if receiver.capacity() > 0 {
                    //info!("{} got frames: {}",prefix, receiver.capacity());
                    while let Some(desc) = receiver.read(){
                        //info!("{} got descriptor: {:?}",prefix,desc);
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
                                        let tx = tx_map.get(&(interface.ifidx, 0)).unwrap();
                                        tx.send(desc).await.unwrap();
                                    }
                                },
                                EthArp::Eth(packet) => {
                                    //info!("{} eth packet: {:?}",prefix, packet);
                                    let dst_mac: [u8;6] = packet.get_destination().into();
                                    if let Some(dst_ifidx) = local_mac_table.get(&dst_mac){
                                        let tx = tx_map.get(&(*dst_ifidx, 0)).unwrap();
                                        tx.send(desc).await.unwrap();
                                    } else {
                                        let mac_table = mac_table_mutex.read().await;
                                        let dst_ifidx = if let Ok(dst_ifidx) = mac_table.get(&dst_mac.into(),0){
                                            local_mac_table.insert(dst_mac, dst_ifidx);
                                            dst_ifidx
                                        } else {
                                            //info!("{} failed to get dst_ifidx for mac: {:?}",prefix, dst_mac);
                                            continue;
                                        };
                                
                                        let tx = tx_map.get(&(dst_ifidx, 0)).unwrap();
                                        tx.send(desc).await.unwrap();
                                    }
                                },
                            }
                            recv_packet_counter += 1;
                            total_recv_packet_counter += 1;
                        }
                        desc_list.push(desc.addr);
                    }
                }
                receiver.release();
                if recv_packet_counter == rx.thresholds{
                    //info!("RECV interface {} recv threshold reached: {}",ifidx, recv_packet_counter);
                    //info!("RECV descriptors: {:?}", desc_list);
                    let dq = dq_map.get(&(ifidx, queue_id)).unwrap();
                    dq.send(FillComplete::Fill(desc_list.clone())).await.unwrap();
                    desc_list.clear();
                    recv_packet_counter = 0;
                    dq.send(FillComplete::Wake).await.unwrap();
                }
            }
        });
        jh_list.push(jh);
    }

    for ((ifidx, queue_id), mut tx) in res.tx{
        let dq_map = dq_map.clone();
        let jh = tokio::spawn(async move{
        let mut desc_buffer = Vec::with_capacity(FRAMES as usize);
            loop{
                let frames = tx.rx.recv_many(&mut desc_buffer, FRAMES as usize).await;
                //info!("SEND {}:{} got frames: {}",ifidx, queue_id, frames);
                {
                    let mut writer = tx.ring_tx.transmit(frames as u32);
                    let sent_now = writer.insert(desc_buffer.iter().map(|desc| desc.clone()));
                    info!("SEND {}:{} sent {} descriptors",ifidx, queue_id, sent_now);
                    writer.commit();
                    total_send_packet_counter += sent_now;
                    send_packet_counter += sent_now;
                }
                desc_buffer.clear();
                if send_packet_counter == tx.thresholds{
                    //info!("SEND interface {}, send threshold reached: {}",ifidx, send_packet_counter);
                    let dp_tx = dq_map.get(&(ifidx, queue_id)).unwrap();
                    dp_tx.send(FillComplete::Complete(send_packet_counter)).await.unwrap();
                    send_packet_counter = 0;
                    tx.ring_tx.wake();
                }
                if tx.ring_tx.needs_wakeup(){
                    tx.ring_tx.wake();
                }
            }
        });
        jh_list.push(jh);
    }

    for ((ifidx, queue_id), mut dq) in res.fq_cq{
        let jh = tokio::spawn(async move{
            while let Some(fill_complete) = dq.rx.recv().await{
                match fill_complete{
                    FillComplete::Fill(recv_frame_buffer_list) => {
                        //info!("FILL {}:{} got fill request for {} descriptors",ifidx, queue_id, recv_frame_buffer_list.len());
                        let mut writer = dq.fq_cq.fill(recv_frame_buffer_list.len() as u32);
                        writer.insert(recv_frame_buffer_list.iter().map(|k| k.clone()));
                        writer.commit();
                    },
                    FillComplete::Complete(send_packet_counter) => {
                        let mut reader = dq.fq_cq.complete(send_packet_counter);
                        while reader.read().is_some() {
                            //comp_temp += 1;
                        }
                        //comp_now = comp_temp;
                        reader.release();
                    },
                    FillComplete::Wake => {
                        if dq.fq_cq.needs_wakeup(){
                            dq.fq_cq.wake();
                        }
                    }
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

async fn receiver(ring_rx_list: Vec<RingRx>) -> anyhow::Result<()>{
    Ok(())
}

pub async fn interface_runner(
    interface: Interface,
    xsk_map: Arc<Mutex<XskMap<MapData>>>,
    interface_queue_table: Arc<Mutex<BpfHashMap<MapData, InterfaceQueue, u32>>>,
    mut rx: HashMap<u32,Arc<RwLock<tokio::sync::mpsc::Receiver<Arc<RwLock<[u8]>>>>>>,
    recv_tx: tokio::sync::mpsc::Sender<(u32,Arc<RwLock<[u8]>>)>,
    mut idx: u32,
) -> anyhow::Result<()>{

    const FRAMES: u32 = 64;
    // FILL_THRESHOLD is 3/4th of BUFFER_SIZE
    const FILL_THRESHOLD: u32 = (BUFFER_SIZE / 4) * 3;
    const COMPLETE_THRESHOLD: u32 = (BUFFER_SIZE / 4) * 3;
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
        let mut total_fill_count = 0;
        let mut total_comp_count = 0;
        let (mut fq_cq, mut ring_rx, mut ring_tx,mut recv_frame_buffer_list,  mut send_frame_buffer_list, thresholds) ={
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

            let mut send_frame_buffer_list = Vec::new();
            for i in 0..umem.len_frames(){
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

            (fq_cq, ring_rx, ring_tx ,recv_frame_buffer_list, send_frame_buffer_list, thresholds)
        };

        let rx = rx.remove(&queue_id).unwrap();
        let mut rcv_interval = tokio::time::interval(Duration::from_nanos(10));
        let recv_tx = recv_tx.clone();

        let (tx_fc, mut rx_fc) = tokio::sync::mpsc::channel(10000);
        let tx_fc_fill = tx_fc.clone();
        let tx_fc_complete = tx_fc.clone();

        let jh = tokio::spawn(async move{
            loop{
                if let Some(fill_complete) = rx_fc.recv().await{
                    match fill_complete{
                        FillComplete::Fill(recv_frame_buffer_list) => {
                            info!("FILL interface {} got fill request for {} descriptors",interface.ifidx, recv_frame_buffer_list.len());
                            info!("FILL interface {} descriptors: {:?}", interface.ifidx, recv_frame_buffer_list);
                            let mut writer = fq_cq.fill(recv_frame_buffer_list.len() as u32);
                            writer.insert(recv_frame_buffer_list.iter().map(|k| k.clone()));
                            writer.commit();
                            total_fill_count += recv_frame_buffer_list.len();
                            info!("FILL filled {}, total fill count: {}",recv_frame_buffer_list.len(), total_fill_count);
                        },
                        FillComplete::Complete(send_packet_counter) => {
                            let mut reader = fq_cq.complete(send_packet_counter);
                            info!("COMPLETE interface {} got complete request for {} descriptors",interface.ifidx, send_packet_counter);
                            while reader.read().is_some() {
                                //comp_temp += 1;
                            }
                            //comp_now = comp_temp;
                            reader.release();
                            total_comp_count += send_packet_counter;
                            info!("COMPLETE interface {}, completed {}, total complete count: {}",interface.ifidx, send_packet_counter, total_comp_count);
                        },
                        FillComplete::Wake => {
                            //if fq_cq.needs_wakeup(){
                                info!("FILL interface {} wake up",interface.ifidx);
                                fq_cq.wake();
                            //}
                        }
                    }
                }
            }
        });
        jh_list.push(jh);

        let jh = tokio::spawn(async move{
            let mut rx = rx.write().await;
            let mut buffer = Vec::with_capacity(FRAMES as usize);
            loop{
                let sent_now: u32;
                let frames = rx.recv_many(&mut buffer, FRAMES as usize).await;
                info!("SEND interface {} got frames: {} to be sent",interface.ifidx, frames);
                let mut desc_list = Vec::with_capacity(frames as usize);
                for i in 0..frames as usize{
                    let msg = &buffer[i];
                    let msg = msg.write().await;
                    let (sb, sd) = &mut send_frame_buffer_list[i];
                    sb[..msg.len()].copy_from_slice(&msg); 
                    sd.len = msg.len() as u32;
                    desc_list.push(*sd);
                }
                {
                    let mut writer = ring_tx.transmit(frames as u32);
                    sent_now = writer.insert(desc_list.iter().map(|desc| desc.clone()));
                    info!("SEND interface {}, sent {} descriptors",interface.ifidx, sent_now);
                    writer.commit();
                    total_send_packet_counter += sent_now;
                    send_packet_counter += sent_now;
                }
                info!("SEND interface {} total sent packet: {}", interface.ifidx, total_send_packet_counter);
                buffer.clear();
                if ring_tx.needs_wakeup(){
                    ring_tx.wake();
                }

                if send_packet_counter == thresholds{
                    info!("SEND interface {}, send threshold reached: {}",interface.ifidx, send_packet_counter);
                    tx_fc_complete.send(FillComplete::Complete(send_packet_counter)).await.unwrap();
                    send_packet_counter = 0;
                    ring_tx.wake();
                }
                
            }
        });
        jh_list.push(jh);

        let jh = tokio::spawn(async move {
            let mut desc_list = Vec::new();
            loop{
                rcv_interval.tick().await;
                let avail = ring_rx.available();
                let mut receiver = ring_rx.receive(FRAMES);
                if receiver.capacity() > 0 {
                    info!("RECV interface {}, got frames: {}",interface.ifidx, receiver.capacity());
                    info!("RECV interface {}, available: {}",interface.ifidx, avail);
                    while let Some(desc) = receiver.read(){
                        info!("RECV interface {}, got descriptor: {:?}",interface.ifidx, desc);
                        let buf_idx = (desc.addr / FRAME_SIZE as u64) * FRAME_SIZE as u64;
                        let offset = desc.addr - buf_idx;
                        if let Some(buf) = recv_frame_buffer_list.get_mut(&buf_idx){
                            let d = &buf.as_ref()[offset as usize..];
                            let b: [u8;PAYLOAD_SIZE as usize] = d.try_into().unwrap();
                            recv_tx.send((interface.ifidx, Arc::new(RwLock::new(b)))).await.unwrap();
                            recv_packet_counter += 1;
                            total_recv_packet_counter += 1;
                        }
                        info!("RECV interface {} pushing desc.addr: {}",interface.ifidx, desc.addr);
                        desc_list.push(desc.addr);
                        //info!("desc list: {:?}", desc_list);
                    }
                    receiver.release();

                    if recv_packet_counter == thresholds{
                        info!("RECV interface {} recv threshold reached: {}",interface.ifidx, recv_packet_counter);
                        //info!("RECV descriptors: {:?}", desc_list);
                        tx_fc_fill.send(FillComplete::Fill(desc_list.clone())).await.unwrap();
                        desc_list.clear();
                        recv_packet_counter = 0;
                        tx_fc_fill.send(FillComplete::Wake).await.unwrap();
                    }
                    info!("RECV interface {}, total received packet: {}", interface.ifidx, total_recv_packet_counter);
                } else {
                    //tx_fc_fill.send(FillComplete::Wake).await.unwrap();
                }
            }
        });
        jh_list.push(jh);
        idx += 1;
    }
    
    futures::future::join_all(jh_list).await;

    Ok(())
}

enum FillComplete{
    Fill(Vec<u64>),
    Complete(u32),
    Wake,
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