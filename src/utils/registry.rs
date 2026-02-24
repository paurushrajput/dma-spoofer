use anyhow::{bail, Result};
use memprocfs::{Vmm, VmmRegValueType};

const NIC_CLASS_GUID: &str = "{4d36e972-e325-11ce-bfc1-08002be10318}";

pub struct RegistrySpoofer<'a> {
    vmm: &'a Vmm<'a>,
}

impl<'a> RegistrySpoofer<'a> {
    pub fn new(vmm: &'a Vmm<'a>) -> Self {
        Self { vmm }
    }

    pub fn set_nic_mac(&self, mac: &[u8; 6]) -> Result<()> {
        let mac_str = format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        println!("[*] Setting registry NetworkAddress: {}", mac_str);

        for control_set in &["ControlSet001", "CurrentControlSet"] {
            let base_path = format!(
                "HKLM\\SYSTEM\\{}\\Control\\Class\\{}",
                control_set, NIC_CLASS_GUID
            );

            if let Ok(class_key) = self.vmm.reg_key(&base_path) {
                if let Ok(subkeys) = class_key.subkeys() {
                    for subkey in subkeys {
                        if !subkey.name.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }

                        let adapter_path = format!("{}\\{}", base_path, subkey.name);

                        if self.is_physical_adapter(&adapter_path) {
                            println!("    [*] Found adapter at {}\\{}", control_set, subkey.name);

                            if let Err(e) = self.write_network_address(&adapter_path, &mac_str) {
                                println!("    [!] Failed to write NetworkAddress: {}", e);
                            } else {
                                println!("    [+] Set NetworkAddress in {}", control_set);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_physical_adapter(&self, path: &str) -> bool {
        let driver_desc_path = format!("{}\\DriverDesc", path);
        if let Ok(value) = self.vmm.reg_value(&driver_desc_path) {
            if let Ok(VmmRegValueType::REG_SZ(desc)) = value.value() {
                let desc_lower = desc.to_lowercase();
                return desc_lower.contains("intel")
                    || desc_lower.contains("realtek")
                    || desc_lower.contains("ethernet")
                    || desc_lower.contains("wireless")
                    || desc_lower.contains("wifi")
                    || desc_lower.contains("network");
            }
        }
        false
    }

    fn write_network_address(&self, adapter_path: &str, mac_str: &str) -> Result<()> {
        let value_path = format!("{}\\NetworkAddress", adapter_path);
        let vfs_path = self.reg_path_to_vfs(&value_path)?;

        let mut data: Vec<u8> = mac_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&[0, 0]);

        self.vmm.vfs_write(&vfs_path, data, 0);

        Ok(())
    }

    fn reg_path_to_vfs(&self, reg_path: &str) -> Result<String> {
        let vfs = reg_path
            .replace("HKLM\\", "/registry/HKLM/")
            .replace("\\", "/");
        Ok(vfs)
    }

    pub fn list_nic_adapters(&self) -> Result<()> {
        let base_path = format!(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{}",
            NIC_CLASS_GUID
        );

        println!("[*] Listing NIC adapters in registry...");
        println!("    Path: {}", base_path);

        let class_key = self.vmm.reg_key(&base_path)?;
        let subkeys = class_key.subkeys()?;

        for subkey in subkeys {
            if !subkey.name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let adapter_path = format!("{}\\{}", base_path, subkey.name);

            let driver_desc = self
                .get_reg_string(&format!("{}\\DriverDesc", adapter_path))
                .unwrap_or_else(|_| "Unknown".to_string());

            let net_addr = self
                .get_reg_string(&format!("{}\\NetworkAddress", adapter_path))
                .unwrap_or_else(|_| "(not set)".to_string());

            println!();
            println!("    [{}] {}", subkey.name, driver_desc);
            println!("        NetworkAddress: {}", net_addr);
        }

        Ok(())
    }

    fn get_reg_string(&self, path: &str) -> Result<String> {
        let value = self.vmm.reg_value(path)?;
        match value.value()? {
            VmmRegValueType::REG_SZ(s) => Ok(s),
            _ => bail!("Not a string value"),
        }
    }
}
