use anyhow::{bail, Result};
use memprocfs::{Vmm, VmmRegValueType};
use uuid::Uuid;

use super::paths::*;
use super::types::{NicGuid, RegistryTrace, RegistryValueType};

pub struct RegistryTraceSpoofer<'a> {
    vmm: &'a Vmm<'a>,
    traces: Vec<RegistryTrace>,
    nic_guids: Vec<NicGuid>,
}

impl<'a> RegistryTraceSpoofer<'a> {
    pub fn new(vmm: &'a Vmm<'a>) -> Result<Self> {
        let mut spoofer = Self {
            vmm,
            traces: Vec::new(),
            nic_guids: Vec::new(),
        };

        spoofer.enumerate()?;

        Ok(spoofer)
    }

    fn enumerate(&mut self) -> Result<()> {
        self.traces.clear();
        self.nic_guids.clear();

        self.enumerate_machine_guid();
        self.enumerate_product_id();
        self.enumerate_build_guid();
        self.enumerate_install_date();
        self.enumerate_sqm_id();
        self.enumerate_nic_guids();

        Ok(())
    }

    fn enumerate_machine_guid(&mut self) {
        let path = format!("{}\\{}", MACHINE_GUID_PATH, MACHINE_GUID_VALUE);
        if let Ok(value) = self.read_string(&path) {
            self.traces.push(RegistryTrace::new(
                MACHINE_GUID_PATH.to_string(),
                MACHINE_GUID_VALUE.to_string(),
                RegistryValueType::String,
                value,
                "Machine GUID - Unique identifier for this Windows installation".to_string(),
            ));
        }
    }

    fn enumerate_product_id(&mut self) {
        let path = format!("{}\\{}", WINDOWS_NT_PATH, PRODUCT_ID_VALUE);
        if let Ok(value) = self.read_string(&path) {
            self.traces.push(RegistryTrace::new(
                WINDOWS_NT_PATH.to_string(),
                PRODUCT_ID_VALUE.to_string(),
                RegistryValueType::String,
                value,
                "Windows Product ID - Derived from license key".to_string(),
            ));
        }
    }

    fn enumerate_build_guid(&mut self) {
        let path = format!("{}\\{}", WINDOWS_NT_PATH, BUILD_GUID_VALUE);
        if let Ok(value) = self.read_string(&path) {
            self.traces.push(RegistryTrace::new(
                WINDOWS_NT_PATH.to_string(),
                BUILD_GUID_VALUE.to_string(),
                RegistryValueType::String,
                value,
                "Build GUID - Tracked by Vanguard".to_string(),
            ));
        }
    }

    fn enumerate_install_date(&mut self) {
        let path = format!("{}\\{}", WINDOWS_NT_PATH, INSTALL_DATE_VALUE);
        if let Ok(value) = self.read_dword(&path) {
            self.traces.push(RegistryTrace::new(
                WINDOWS_NT_PATH.to_string(),
                INSTALL_DATE_VALUE.to_string(),
                RegistryValueType::Dword,
                format!("{} (0x{:08X})", value, value),
                "Windows Install Date - Unix timestamp".to_string(),
            ));
        }
    }

    fn enumerate_sqm_id(&mut self) {
        let path = format!("{}\\{}", SQM_CLIENT_PATH, SQM_MACHINE_ID_VALUE);
        if let Ok(value) = self.read_string(&path) {
            self.traces.push(RegistryTrace::new(
                SQM_CLIENT_PATH.to_string(),
                SQM_MACHINE_ID_VALUE.to_string(),
                RegistryValueType::String,
                value,
                "SQM Machine ID - Telemetry identifier".to_string(),
            ));
        }
    }

    fn enumerate_nic_guids(&mut self) {
        if let Ok(key) = self.vmm.reg_key(NETWORK_CARDS_PATH) {
            if let Ok(subkeys) = key.subkeys() {
                for subkey in subkeys {
                    let adapter_path = format!("{}\\{}", NETWORK_CARDS_PATH, subkey.name);

                    let description = self
                        .read_string(&format!("{}\\Description", adapter_path))
                        .unwrap_or_default();

                    let service_name = self
                        .read_string(&format!("{}\\{}", adapter_path, SERVICE_NAME_VALUE))
                        .unwrap_or_default();

                    if !service_name.is_empty() {
                        self.nic_guids.push(NicGuid::new(
                            subkey.name.clone(),
                            description,
                            service_name.clone(),
                            service_name,
                        ));
                    }
                }
            }
        }
    }

    fn read_string(&self, path: &str) -> Result<String> {
        let value = self.vmm.reg_value(path)?;
        match value.value()? {
            VmmRegValueType::REG_SZ(s) => Ok(s),
            _ => bail!("Not a string value"),
        }
    }

    fn read_dword(&self, path: &str) -> Result<u32> {
        let value = self.vmm.reg_value(path)?;
        match value.value()? {
            VmmRegValueType::REG_DWORD(v) => Ok(v),
            _ => bail!("Not a DWORD value"),
        }
    }

    fn write_string(&self, path: &str, data: &str) -> Result<()> {
        let vfs_path = self.reg_path_to_vfs(path)?;

        let mut bytes: Vec<u8> = data.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);

        self.vmm.vfs_write(&vfs_path, bytes, 0);

        Ok(())
    }

    fn write_dword(&self, path: &str, value: u32) -> Result<()> {
        let vfs_path = self.reg_path_to_vfs(path)?;
        let bytes = value.to_le_bytes().to_vec();
        self.vmm.vfs_write(&vfs_path, bytes, 0);
        Ok(())
    }

    fn reg_path_to_vfs(&self, reg_path: &str) -> Result<String> {
        let vfs = reg_path
            .replace("HKLM\\", "/registry/HKLM/")
            .replace("\\", "/");
        Ok(vfs)
    }

    pub fn list(&self) -> Result<()> {
        println!("\n[+] Registry Traces (Anti-Cheat Tracked):");

        if self.traces.is_empty() {
            println!("    No registry traces found");
        } else {
            for trace in &self.traces {
                println!();
                println!("    [{}]", trace.description);
                println!("        Path: {}\\{}", trace.path, trace.value_name);
                println!("        Value: {}", trace.current_value);
            }
        }

        println!("\n[+] NIC GUIDs (Network Adapter Identifiers):");

        if self.nic_guids.is_empty() {
            println!("    No NIC GUIDs found");
        } else {
            for nic in &self.nic_guids {
                println!();
                println!("    [{}] {}", nic.adapter_index, nic.description);
                println!("        ServiceName: {}", nic.service_name);
            }
        }

        println!();
        println!(
            "    Total: {} traces, {} NIC GUIDs",
            self.traces.len(),
            self.nic_guids.len()
        );

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        println!("\n[*] Spoofing registry traces...");

        let mut spoofed = 0;

        for trace in &self.traces {
            let new_value = self.generate_value(&trace.value_type, &trace.value_name);

            println!();
            println!("    [{}]", trace.value_name);
            println!("        Old: {}", trace.current_value);
            println!("        New: {}", new_value);

            let full_path = trace.full_path();

            let result = match trace.value_type {
                RegistryValueType::String => self.write_string(&full_path, &new_value),
                RegistryValueType::Dword => {
                    let v = new_value.parse::<u32>().unwrap_or(0);
                    self.write_dword(&full_path, v)
                }
                _ => Ok(()),
            };

            match result {
                Ok(()) => {
                    println!("        Status: OK");
                    spoofed += 1;
                }
                Err(e) => {
                    println!("        Status: FAILED - {}", e);
                }
            }
        }

        println!("\n[+] Spoofed {} registry values", spoofed);

        self.spoof_nic_guids()?;

        Ok(())
    }

    fn spoof_nic_guids(&self) -> Result<()> {
        println!("\n[*] Spoofing NIC GUIDs...");

        for nic in &self.nic_guids {
            let new_guid = format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase());

            println!();
            println!("    [{}] {}", nic.adapter_index, nic.description);
            println!("        Old: {}", nic.service_name);
            println!("        New: {}", new_guid);

            let path = format!(
                "{}\\{}\\{}",
                NETWORK_CARDS_PATH, nic.adapter_index, SERVICE_NAME_VALUE
            );

            match self.write_string(&path, &new_guid) {
                Ok(()) => println!("        Status: OK"),
                Err(e) => println!("        Status: FAILED - {}", e),
            }
        }

        Ok(())
    }

    fn generate_value(&self, value_type: &RegistryValueType, name: &str) -> String {
        match value_type {
            RegistryValueType::String => {
                if name.contains("Guid") || name.contains("GUID") || name.contains("Id") {
                    if name == "ProductId" {
                        self.generate_product_id()
                    } else {
                        Uuid::new_v4().to_string()
                    }
                } else {
                    Uuid::new_v4().to_string()
                }
            }
            RegistryValueType::Dword => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32;
                now.to_string()
            }
            _ => Uuid::new_v4().to_string(),
        }
    }

    fn generate_product_id(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut state = seed;
        let mut random = || -> u32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 33) as u32
        };

        format!(
            "{:05}-{:05}-{:05}-{:05}",
            random() % 100000,
            random() % 100000,
            random() % 100000,
            random() % 100000
        )
    }

    pub fn trace_count(&self) -> usize {
        self.traces.len() + self.nic_guids.len()
    }
}
