use std::{fmt::Display, net::Ipv4Addr, process::exit, str::FromStr};

use inquire::{error::CustomUserError, length, parser::CustomTypeParser, required, ui::RenderConfig, CustomType, Text};
use log::info;
use switch_rs_common::{FlowKey, FlowNextHop};
use clap::{ArgMatches, FromArgMatches, Parser, Subcommand};
use crate::flow_manager::flow_manager::FlowManagerClient;

pub struct Cli{
    flow_manager_client: FlowManagerClient,
}

impl Cli {
    pub fn new(flow_manager_client: FlowManagerClient) -> Self {
        Cli{
            flow_manager_client
        }
    }
    pub async fn run(&self) -> anyhow::Result<()> {
        cli(self.flow_manager_client.clone()).await
    }
}

/*
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Commander {
    #[command(subcommand)]
    command: Option<Commands>,
}
*/

#[derive(Clone, Parser, Debug)]
enum Commands {
    #[command(subcommand)]
    Show(ShowCommands),
    #[command(subcommand)]
    Set(SetCommands),
    Exit,
}

#[derive(Clone, Parser, Debug)]
enum ShowCommands {
    Stats,
    Flows,
    MaxPackets,
    FlowTimeout,
    FlowletSize,
}

#[derive(Clone, Parser, Debug)]
enum SetCommands {
    MaxPackets{max_packets: u64},
    FlowTimeout{flow_timeout: u64},
    FlowletSize{flowlet_size: u32},
    PauseOff,
    PauseOn,
}


async fn cli(client: FlowManagerClient) -> anyhow::Result<()> {

    let jh = tokio::spawn(async move {
        loop{
            
            let input = Text::new("Cmd -> ")
            .with_autocomplete(&root_suggester)
            .with_validator(required!())
            //.with_validator(length!(10))
            .prompt()
            .unwrap();

            let mut input_string = input.split_whitespace().collect::<Vec<_>>();
            input_string.insert(0, "");

            let cmds = Commands::parse_from(input_string);
            match cmds {
                Commands::Show(show_command) => {
                    match show_command{
                        ShowCommands::Flows => {
                            let flows = client.list_flows().await.unwrap();
                            let mut flows_list = flows.iter().collect::<Vec<_>>();
                            flows_list.sort_by_key(|(flow_key, _)| *flow_key);
                            for (flow_key, (flow, last_updated)) in flows.iter(){
                                println!("Flow {} {}", display_flow_key(flow_key), display_flow_next_hop(flow, last_updated));
                            }
                        },
                        ShowCommands::Stats => {
                            let stats = client.list_stats().await.unwrap();
                            let mut stats_list = stats.iter().collect::<Vec<_>>();
                            stats_list.sort_by_key(|(ifidx, _)| *ifidx);
                            for (ifidx, stats) in stats_list.iter(){
                                println!("Interface {} {}", ifidx, stats);
                            }
                        },
                        ShowCommands::MaxPackets => {
                            let max_packets = client.show_max_packets().await.unwrap();
                            println!("max_packets: {}", max_packets);
                        },
                        ShowCommands::FlowTimeout => {
                            let flow_timeout = client.show_flow_timeout().await.unwrap();
                            println!("flow_timeout: {}", flow_timeout);
                        },
                        ShowCommands::FlowletSize => {
                            let flowlet_size = client.show_flowlet_size().await.unwrap();
                            println!("flowlet_size: {}", flowlet_size);
                        }
                    }
                },
                Commands::Set(set_command) => {
                    match set_command{
                        SetCommands::MaxPackets{max_packets} => {
                            println!("Setting max_packets to {}", max_packets);
                            client.set_max_packets(max_packets).await.unwrap();
                            println!("max_packets set to {}", client.show_max_packets().await.unwrap());
                        },
                        SetCommands::FlowTimeout{flow_timeout} => {
                            println!("Setting flow_timeout to {}", flow_timeout);
                            client.set_flow_timeout(flow_timeout).await.unwrap();
                            println!("flow_timeout set to {}", client.show_flow_timeout().await.unwrap());
                        },
                        SetCommands::PauseOff => {
                            println!("Turning pause off");
                            client.toggle_pause(false).await.unwrap();
                            println!("pause is {}", client.show_pause().await.unwrap());
                        },
                        SetCommands::PauseOn => {
                            println!("Turning pause on");
                            client.toggle_pause(true).await.unwrap();
                            println!("pause is {}", client.show_pause().await.unwrap());
                        },
                        SetCommands::FlowletSize{flowlet_size} => {
                            println!("Setting flowlet_size to {}", flowlet_size);
                            client.set_flowlet_size(flowlet_size).await.unwrap();
                            println!("flowlet_size set to {}", client.show_flowlet_size().await.unwrap());
                        }
                    }
                },
                Commands::Exit => {
                    exit(0);
                }
            }
        }
    });
    jh.await?;
    Ok(())
}

fn root_suggester(val: &str) -> Result<Vec<String>, CustomUserError> {
    let suggestions = [
        "set max-packets",
        "set flow-timeout",
        "set flow-size",
        "set pause-off",
        "set pause-on",
        "show flows",
        "show stats",
        "show flowlet-size",
        "show max-packets",
        "show flow-timeout",
        "exit",
    ];

    let val_lower = val.to_lowercase();

    Ok(suggestions
        .iter()
        .filter(|s| s.to_lowercase().contains(&val_lower))
        .map(|s| String::from(*s))
        .collect())
}


fn display_flow_key(flow_key: &FlowKey) -> String {
    let src_ip = Ipv4Addr::from(flow_key.src_ip);
    let dst_ip = Ipv4Addr::from(flow_key.dst_ip);
    let src_port = flow_key.src_port;
    let dst_port = flow_key.dst_port;
    format!("src {}:{} dst {}:{}",
        src_ip, src_port, dst_ip, dst_port)
}

fn display_flow_next_hop(flow_next_hop: &FlowNextHop, last_updated: &tokio::time::Instant) -> String {
    let src_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        flow_next_hop.src_mac[0], flow_next_hop.src_mac[1], flow_next_hop.src_mac[2],
        flow_next_hop.src_mac[3], flow_next_hop.src_mac[4], flow_next_hop.src_mac[5]);
    let dst_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        flow_next_hop.dst_mac[0], flow_next_hop.dst_mac[1], flow_next_hop.dst_mac[2],
        flow_next_hop.dst_mac[3], flow_next_hop.dst_mac[4], flow_next_hop.dst_mac[5]);
    let oif = flow_next_hop.oif_idx;
    let packets = flow_next_hop.packet_count;
    let last_updated = last_updated.elapsed().as_secs();
    let flowlet_size = flow_next_hop.flowlet_size;
    format!("src_mac {} dst_mac {} oif {} packets {}, flowlet_size: {}, last_updated {}s ago",
        src_mac, dst_mac, oif, packets, flowlet_size, last_updated)
}