use std::process::exit;

use inquire::{error::CustomUserError, length, required, ui::RenderConfig, Text};

pub struct Cli{}

impl Cli {
    pub fn new() -> Self {
        Cli{}
    }
    pub async fn run(&self) -> anyhow::Result<()> {
        cli().await
    }
}

enum CliCommands{
    Config(ConfigCommands),
    Stats(StatsCommands),
    Exit,
}
enum ConfigCommands{
    Add(ConfigItems),
    Remove(ConfigItems),
    Show(ConfigItems),
}
enum ConfigItems{
    RouteTable,
    MacTable,
}
enum StatsCommands{
    Get(StatsItems),
    Reset(StatsItems),
}

enum StatsItems{
    Sent,
    Received,
}

async fn cli(/*client: UserSpaceClient*/) -> anyhow::Result<()> {
    let jh = tokio::spawn(async move {
        loop{
            let command = Text::new("Cmd -> ")
            .with_autocomplete(&suggester)
            .with_validator(required!())
            //.with_validator(length!(10))
            .prompt()
            .unwrap();
    
            match command.as_str() {
                "RouteTable" => {

                },
                "NeighborTable" => {

                },
                "ForwardingTable" => {

                },
                "Exit" => {
                    exit(0)
                },
                _ => {
                    println!("Command not found");
                }
            }
            
        }
    });
    jh.await?;
    Ok(())
}

fn suggester(val: &str) -> Result<Vec<String>, CustomUserError> {
    let suggestions = [
        "RouteTable",
        "NeighborTable",
        "ForwardingTable",
        "Exit"
    ];

    let val_lower = val.to_lowercase();

    Ok(suggestions
        .iter()
        .filter(|s| s.to_lowercase().contains(&val_lower))
        .map(|s| String::from(*s))
        .collect())
}