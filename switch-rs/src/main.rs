use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use anyhow::Context;
use aya::maps::{MapData, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::HashMap as BpfHashMap};
use aya_log::BpfLogger;
use clap::Parser;
use env_logger::fmt;
use log::{debug, info, warn};
use tokio::signal;
use switch_rs_common::{ArpEntry, FlowKey, FlowNextHop, InterfaceConfig, InterfaceConfiguration, InterfaceQueue};
use af_xdp::{
    interface::interface::{get_interface_index, get_interface_mac},
    af_xdp::AfXdp,
};
use crate::af_xdp::interface::interface::Interface;
use crate::network_state::network_state::NetworkState;
use crate::flow_manager::flow_manager::FlowManager;

pub mod af_xdp;
pub mod cli;
pub mod handler;
pub mod network_state;
pub mod flow_manager;


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
        program.attach(&iface, XdpFlags::DRV_MODE)
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

    let flow_table = if let Some(flow_table) = bpf.take_map("FLOWTABLE"){
        let flow_table: BpfHashMap<MapData, FlowKey, FlowNextHop> = BpfHashMap::try_from(flow_table).unwrap();
        flow_table
    } else {
        panic!("FLOWTABLE map not found");
    };

    let arp_table = if let Some(arp_table) = bpf.take_map("ARPTABLE"){
        let arp_table: BpfHashMap<MapData, u32, ArpEntry> = BpfHashMap::try_from(arp_table).unwrap();
        arp_table
    } else {
        panic!("ARPTABLE map not found");
    };

    let interface_configuration = if let Some(interface_configuration) = bpf.take_map("INTERFACECONFIGURATION"){
        let interface_configuration: BpfHashMap<MapData, u32, InterfaceConfiguration> = BpfHashMap::try_from(interface_configuration).unwrap();
        interface_configuration
    } else {
        panic!("INTERFACECONFIGURATION map not found");
    };

    let mac_table_mutex = Arc::new(Mutex::new(mac_table));
    let arp_table_mutex = Arc::new(Mutex::new(arp_table));
    let interface_configuration_mutex = Arc::new(Mutex::new(interface_configuration));

    let mut flow_manager = FlowManager::new();
    let mut network_state = NetworkState::new(interface_list.clone(), interface_configuration_mutex);
    let handler = handler::handler::Handler::new(interface_list.clone(), mac_table_mutex, arp_table_mutex, network_state.client(), flow_manager.client());
    let afxdp = AfXdp::new(interface_list.clone(), xsk_map, interface_queue_table);
    let mut jh_list = Vec::new();
    let handler_clone = handler.clone();

    let jh = tokio::spawn(async move {
        flow_manager.run(flow_table).await;
    });
    jh_list.push(jh);
    let jh = tokio::spawn(async move {
        network_state.run().await;
    });
    jh_list.push(jh);


    let jh = tokio::spawn(async move {
        afxdp.run(handler_clone).await.unwrap();
    });
    jh_list.push(jh);
    
    info!("Waiting for Ctrl-C...");
    futures::future::join_all(jh_list).await;
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}


