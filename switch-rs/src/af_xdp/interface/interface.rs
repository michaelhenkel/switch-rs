use std::{ffi::CString, path::Path};
#[derive(Clone, Debug)]
pub struct Interface{
    pub name: String,
    pub ifidx: u32,
    pub mac: [u8;6],
    pub queues: u32,
}

impl Interface{
    pub async fn new(name: String) -> anyhow::Result<Self>{
        let ifidx = match get_interface_index(&name){
            Ok(ifidx) => ifidx,
            Err(e) => {
                return Err(anyhow::anyhow!("failed to get interface index: {:?}", e));
            }
        };
        let mac = match get_interface_mac(&name){
            Ok(mac) => {
                mac
            },
            Err(e) => {
                return Err(anyhow::anyhow!("failed to get MAC address: {:?}", e));
            }
        };
        let queues = match get_queues(name.clone()){
            Ok(queues) => queues,
            Err(e) => {
                return Err(anyhow::anyhow!("failed to get queues: {:?}", e));
            }
        };
        Ok(Self{
            name,
            ifidx,
            mac,
            queues
        })
    }
}

fn get_queues(intf: String) -> anyhow::Result<u32> {
    let p = format!("/sys/class/net/{}/queues/", intf);
    let path = Path::new(&p);
    let entries = match path.read_dir() {
        Ok(entries) => entries,
        Err(err) => panic!("Error reading the directory: {:?}", err),
    };
    // the directory should contain multiple rx- and tx- entries. They are indexed like rx-0, rx-1, ... Count the number of rx- and tx- entries
    let mut rx_count = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => panic!("Error reading entry: {:?}", err),
        };
        let file_name = entry.file_name();
        let file_name = match file_name.to_str() {
            Some(file_name) => file_name,
            None => panic!("Error converting file name to string"),
        };
        if file_name.starts_with("rx-") {
            rx_count += 1;
        }
    }
    Ok(rx_count)
}

pub fn get_interface_index(interface_name: &str) -> anyhow::Result<u32> {
    let interface_name_cstring = CString::new(interface_name)?;
    let interface_index = unsafe { libc::if_nametoindex(interface_name_cstring.as_ptr()) };
    if interface_index == 0 {
        Err(anyhow::anyhow!(
            "failed to get interface index for interface {}",
            interface_name
        ))
    } else {
        
        Ok(interface_index)
    }
}

pub fn get_interface_mac(interface_name: &str) -> anyhow::Result<[u8; 6]> {
    match mac_address::mac_address_by_name(interface_name) {
        Ok(mac) => {
            match mac{
                Some(mac) => Ok(mac.bytes()),
                None => Err(anyhow::anyhow!(
                    "failed to get MAC address for interface {}",
                    interface_name
                )),
            }
        },
        Err(e) => Err(anyhow::anyhow!(
            "failed to get MAC address for interface {}: {}",
            interface_name,
            e
        )),
    }
}