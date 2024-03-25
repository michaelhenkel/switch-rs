use std::{net::Ipv4Addr, process::exit};

use inquire::{error::CustomUserError, length, required, ui::RenderConfig, Text};
use switch_rs_common::{FlowKey, FlowNextHop};

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


enum CliCommands{
    Get{
        ifidx: u32,
    },
    List(CliItem),
    Exit(),
}

enum CliItem{
    Stats,
    Flows
}

async fn cli(client: FlowManagerClient) -> anyhow::Result<()> {
    let jh = tokio::spawn(async move {
        loop{
            let command = Text::new("Cmd -> ")
            .with_autocomplete(&suggester)
            .with_validator(required!())
            //.with_validator(length!(10))
            .prompt()
            .unwrap();

            let command = parse_command(command.as_str());

            match command {
                CliCommands::Get{ifidx} => {
                    let stats = client.get_stats(ifidx).await.unwrap();
                    println!("Interface Stats: {:?}", stats);
                },
                CliCommands::List(cli_item) => {
                    match cli_item{
                        CliItem::Stats => {
                            let stats = client.list_stats().await.unwrap();
                            let mut stats_list = stats.iter().collect::<Vec<_>>();
                            stats_list.sort_by_key(|(ifidx, _)| *ifidx);
                            for (ifidx, stats) in stats_list.iter(){
                                println!("Interface {} {}", ifidx, stats);
                            }
                        },
                        CliItem::Flows => {
                            let flows = client.list_flows().await.unwrap();
                            let mut flows_list = flows.iter().collect::<Vec<_>>();
                            flows_list.sort_by_key(|(flow_key, _)| *flow_key);
                            for (flow_key, (flow, last_updated)) in flows.iter(){
                                println!("Flow {} {}", display_flow_key(flow_key), display_flow_next_hop(flow, last_updated));
                            }
                        }
                    }
                }
                CliCommands::Exit() => {
                    exit(0);
                }
            }
            
        }
    });
    jh.await?;
    Ok(())
}

fn parse_command(command: &str) -> CliCommands {
    let command = command.trim();
    let mut parts = command.split_whitespace();
    match parts.next() {
        Some("get") => {
            let ifidx = parts.next().unwrap().parse().unwrap();
            CliCommands::Get{ifidx}
        },
        Some("list") => {
            let item = parts.next().unwrap();
            parse_list_command(item)
        },
        Some("exit") => CliCommands::Exit(),
        _ => panic!("Invalid command"),
    }
}

fn parse_list_command(item: &str) -> CliCommands {
    match item {
        "stats" => CliCommands::List(CliItem::Stats),
        "flows" => CliCommands::List(CliItem::Flows),
        _ => panic!("Invalid command"),
    }
}

fn suggester(val: &str) -> Result<Vec<String>, CustomUserError> {
    let suggestions = [
        "get <ifidx>",
        "list flows",
        "list stats",
        "update configuration",
        "exit"
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
    format!("src_mac {} dst_mac {} oif {} packets {}, last_updated {}s ago",
        src_mac, dst_mac, oif, packets, last_updated)
}