use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use af_xdp::af_xdp::AfXdpClient;
use anyhow::Context;
use aya::maps::{MapData, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::HashMap as BpfHashMap};
use aya_log::BpfLogger;
use clap::Parser;
use env_logger::fmt;
use log::{debug, error, info, warn};
use tokio::signal;
use switch_rs_common::{InterfaceConfig, InterfaceQueue};
use af_xdp::{
    interface::interface::{get_interface_index, get_interface_mac},
    af_xdp::AfXdp
};
use pnet::packet::{
    //MutablePacket,
    Packet,
    ethernet::{EtherTypes, MutableEthernetPacket},
    arp::{ArpPacket, ArpOperations, /*MutableArpPacket*/},
};
use tokio::sync::RwLock;
use crate::af_xdp::interface::interface::Interface;
pub mod af_xdp;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    ifaces: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let ts = Some(fmt::TimestampPrecision::Micros);
    env_logger::builder()
    .format_timestamp(ts)
    .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut interface_list = HashMap::new();
    for interface in &opt.ifaces{
        let interface = Interface::new(interface.to_string()).await?;
        interface_list.insert(interface.ifidx,interface);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/switch-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/switch-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("switch_rs").unwrap().try_into()?;
    program.load()?;
    for iface in &opt.ifaces {
        program.attach(&iface, XdpFlags::default())
            .context(format!("failed to attach the XDP program to interface {}", iface))?;
    }

    if let Some(interface_count_map) = bpf.take_map("INTERFACECOUNT"){
        let mut interface_count_map: BpfHashMap<MapData, u32, u32> = BpfHashMap::try_from(interface_count_map).unwrap();
        interface_count_map.insert(0, opt.ifaces.len() as u32, 0)?;
    } else {
        panic!("INTERFACEQUEUETABLE map not found");
    }

    if let Some(interface_map) = bpf.take_map("INTERFACEMAP"){
        let mut interface_map: BpfHashMap<MapData, u32, InterfaceConfig> = BpfHashMap::try_from(interface_map).unwrap();
        for (idx, iface) in opt.ifaces.iter().enumerate() {
            let iface_index = get_interface_index(iface)?;
            let mac = get_interface_mac(iface)?;
            let iface_config = InterfaceConfig {
                idx: iface_index,
                mac,
            };
            interface_map.insert(idx as u32, iface_config, 0)?;
        }
    } else {
        panic!("INTERFACEMAP map not found");
    }

    let interface_queue_table = if let Some(interface_queue_table) = bpf.take_map("INTERFACEQUEUETABLE"){
        let interface_queue_table: BpfHashMap<MapData, InterfaceQueue, u32> = BpfHashMap::try_from(interface_queue_table).unwrap();
        interface_queue_table
    } else {
        panic!("INTERFACEQUEUETABLE map not found");
    };

    let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP"){
        let xsk_map: XskMap<MapData> = XskMap::try_from(xsk_map).unwrap();
        xsk_map
    } else {
        panic!("XSKMAP map not found");
    };

    let mac_table = if let Some(mac_table) = bpf.take_map("MACTABLE"){
        let mac_table: BpfHashMap<MapData, [u8;6], u32> = BpfHashMap::try_from(mac_table).unwrap();
        mac_table
    } else {
        panic!("MACTABLE map not found");
    };

    
    let mut afxdp = AfXdp::new(interface_list.clone(), xsk_map, interface_queue_table);
    let afxdp_client = afxdp.client();
    //let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let mut jh_list = Vec::new();
    /*
    let jh = tokio::spawn(async move {
        handler(rx, afxdp_client, interface_list, mac_table).await.unwrap();
    });
    jh_list.push(jh);
    */
    let jh = tokio::spawn(async move {
        afxdp.run2(mac_table).await.unwrap();
    });
    jh_list.push(jh);
    
    info!("Waiting for Ctrl-C...");
    futures::future::join_all(jh_list).await;
    //kernel_handler(interface_list).await?;
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

async fn kernel_handler(interface_list: HashMap<u32, Interface>) -> anyhow::Result<()>{
    let mut receiver_list = HashMap::new();
    let mut sender_list = HashMap::new();
    for (ifidx, interface) in &interface_list{
        let network_interface = pnet::datalink::interfaces().into_iter().find(|iface| iface.name == interface.name).ok_or(anyhow::anyhow!("failed to find interface {}", interface.name))?;
        let (sender, receiver) = match pnet::datalink::channel(&network_interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
        receiver_list.insert(*ifidx, receiver);
        sender_list.insert(*ifidx, Arc::new(Mutex::new(sender)));
    }
    let mut jh_list = Vec::new();
    for (ifidx, receiver) in receiver_list{
        let interface_list = interface_list.clone();
        let sender_list = sender_list.clone();
        let jh = tokio::spawn(async move {
            receive_packet(receiver, interface_list, ifidx, sender_list).await.unwrap();
        });
        jh_list.push(jh);
    }
    futures::future::join_all(jh_list).await;
    Ok(())
}

async fn receive_packet(mut receiver: Box<dyn pnet::datalink::DataLinkReceiver>, interface_list: HashMap<u32, Interface>, ifidx: u32, sender_list: HashMap<u32,Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>>) -> anyhow::Result<()>{
    loop{
        let buf = receiver.next().unwrap();
        info!("received packet on interface {}", ifidx);
        let mut buf = buf.to_vec();
        let eth = MutableEthernetPacket::new(&mut buf).unwrap();
        info!("eth packet: {:?}", eth);
        for (sender_ifidx, sender) in &sender_list{
            if *sender_ifidx == ifidx{
                continue;
            }
            let mut sender = sender.lock().unwrap();
            info!("sending packet to interface {}", sender_ifidx);
            sender.send_to(eth.packet(), None).unwrap()?;
        }
    }
}

async fn handler(
    mut rx: tokio::sync::mpsc::Receiver<(u32, Arc<RwLock<[u8]>>)>,
    mut client: AfXdpClient,
    interface_list: HashMap<u32, Interface>,
    mac_table: BpfHashMap<MapData, [u8;6], u32>,
) -> anyhow::Result<()>{
    const FRAME_SIZE: u32 = 1 << 12;
    const HEADROOM: u32 = 1 << 8;
    const PAYLOAD_SIZE: u32 = FRAME_SIZE - HEADROOM;

    while let Some((ingress_ifidx, packet)) = rx.recv().await {
        let mut s = packet.write().await;
        let mut eth_packet = MutableEthernetPacket::new(&mut s).ok_or(anyhow::anyhow!("failed to parse Ethernet packet"))?;
        match eth_packet.get_ethertype(){
            EtherTypes::Arp => {
                let arp_packet = ArpPacket::new(eth_packet.payload()).ok_or(anyhow::anyhow!("failed to parse ARP packet"))?;
                let op = arp_packet.get_operation();
                match op{
                    ArpOperations::Request => {
                        for (ifidx, interface) in &interface_list{
                            if *ifidx == ingress_ifidx{
                                continue;
                            }
                            eth_packet.set_source(interface.mac.into());
                            let p = eth_packet.packet();
                            let b: [u8;PAYLOAD_SIZE as usize] = p.try_into().unwrap();
                            client.send(*ifidx, 0,Arc::new(RwLock::new(b))).await?;
                            //info!("interface {} transmitted packet 3", ingress_ifidx);
                        }
                    },
                    _ => {}
                }
            }
            EtherTypes::Ipv4 => {
                let dmac = eth_packet.get_destination();
                match mac_table.get(&dmac.into(), 0){
                    Ok(ifidx) => {
                        let p = eth_packet.packet();
                        let b: [u8;PAYLOAD_SIZE as usize] = p.try_into().unwrap();
                        if let Err(e) = client.send(ifidx, 0,Arc::new(RwLock::new(b))).await{
                            error!("failed to send packet to interface {}: {}", ifidx, e);
                        }
                        //info!("interface {} transmitted packet 3", ifidx);
                    },
                    Err(e) => {
                        error!("failed to get interface from MACTABLE: {}", e);
                    }
                }
            }
            _ => {
                continue;
            }
        }
    }
    Ok(())
}
