use anyhow::{bail, Result};
use memprocfs::{Vmm, VmmRegValueType};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::cells::CellNavigator;
use super::hive::RegistryHive;

const DISPLAY_ENUM_PATH: &str = "HKLM\\SYSTEM\\ControlSet001\\Enum\\DISPLAY";

#[derive(Debug, Clone)]
pub struct MonitorInfo {
    pub display_id: String,
    pub device_id: String,
    pub registry_path: String,
    pub edid: Option<Vec<u8>>,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub serial_text: Option<String>,
    pub week: u8,
    pub year: u16,
}

pub struct MonitorSpoofer<'a> {
    vmm: &'a Vmm<'a>,
    rng: StdRng,
}

impl<'a> MonitorSpoofer<'a> {
    pub fn new(vmm: &'a Vmm<'a>, seed: u64) -> Self {
        Self {
            vmm,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn enumerate_monitors(&self) -> Result<Vec<MonitorInfo>> {
        let mut monitors = Vec::new();
        let vfs_display_path = "/registry/HKLM/SYSTEM/ControlSet001/Enum/DISPLAY";

        if let Ok(entries) = self.vmm.vfs_list(vfs_display_path) {
            for entry in entries {
                if !entry.is_directory {
                    continue;
                }
                let display_id = &entry.name;
                let display_vfs_path = format!("{}/{}", vfs_display_path, display_id);

                if let Ok(device_entries) = self.vmm.vfs_list(&display_vfs_path) {
                    for device_entry in device_entries {
                        if !device_entry.is_directory {
                            continue;
                        }
                        let device_id = &device_entry.name;
                        let device_params_path = format!(
                            "HKLM\\SYSTEM\\ControlSet001\\Enum\\DISPLAY\\{}\\{}\\Device Parameters",
                            display_id, device_id
                        );

                        if let Ok(edid_data) = self.read_edid(&device_params_path) {
                            let mut monitor = MonitorInfo {
                                display_id: display_id.clone(),
                                device_id: device_id.clone(),
                                registry_path: device_params_path.clone(),
                                edid: Some(edid_data.clone()),
                                manufacturer: "Unknown".to_string(),
                                model: "Unknown".to_string(),
                                serial_number: "Unknown".to_string(),
                                serial_text: None,
                                week: 0,
                                year: 0,
                            };

                            self.parse_edid(&mut monitor, &edid_data);
                            monitors.push(monitor);
                        }
                    }
                }
            }
            return Ok(monitors);
        }

        let display_key = self.vmm.reg_key(DISPLAY_ENUM_PATH)?;
        let display_subkeys = display_key.subkeys()?;

        for display_subkey in display_subkeys {
            let display_id = &display_subkey.name;
            let display_path = format!("{}\\{}", DISPLAY_ENUM_PATH, display_id);

            if let Ok(display_key) = self.vmm.reg_key(&display_path) {
                if let Ok(device_subkeys) = display_key.subkeys() {
                    for device_subkey in device_subkeys {
                        let device_id = &device_subkey.name;
                        let device_params_path =
                            format!("{}\\{}\\Device Parameters", display_path, device_id);

                        if let Ok(edid_data) = self.read_edid(&device_params_path) {
                            let mut monitor = MonitorInfo {
                                display_id: display_id.clone(),
                                device_id: device_id.clone(),
                                registry_path: device_params_path.clone(),
                                edid: Some(edid_data.clone()),
                                manufacturer: "Unknown".to_string(),
                                model: "Unknown".to_string(),
                                serial_number: "Unknown".to_string(),
                                serial_text: None,
                                week: 0,
                                year: 0,
                            };

                            self.parse_edid(&mut monitor, &edid_data);
                            monitors.push(monitor);
                        }
                    }
                }
            }
        }

        Ok(monitors)
    }

    fn read_edid(&self, device_params_path: &str) -> Result<Vec<u8>> {
        let edid_path = format!("{}\\EDID", device_params_path);
        let value = self.vmm.reg_value(&edid_path)?;

        match value.value()? {
            VmmRegValueType::REG_BINARY(data) => Ok(data),
            _ => bail!("EDID is not binary data"),
        }
    }

    fn parse_edid(&self, monitor: &mut MonitorInfo, edid: &[u8]) {
        if edid.len() < 128 {
            return;
        }

        if edid.len() > 9 {
            let manufacturer_id = ((edid[8] as u16) << 8) | (edid[9] as u16);
            monitor.manufacturer = self.decode_manufacturer_id(manufacturer_id);
        }

        if edid.len() > 11 {
            let product_code = ((edid[11] as u16) << 8) | (edid[10] as u16);
            monitor.model = format!("{:04X}", product_code);
        }

        if edid.len() > 15 {
            let serial_bytes = [edid[12], edid[13], edid[14], edid[15]];
            let serial_u32 = u32::from_le_bytes(serial_bytes);
            if serial_u32 != 0 {
                monitor.serial_number = format!("{}", serial_u32);
            }
        }

        monitor.serial_text = self.extract_text_serial(edid);

        if edid.len() > 17 {
            monitor.week = edid[16];
            monitor.year = 1990 + (edid[17] as u16);
        }
    }

    fn decode_manufacturer_id(&self, manufacturer_id: u16) -> String {
        let char1 = (((manufacturer_id >> 10) & 0x1F) + 64) as u8 as char;
        let char2 = (((manufacturer_id >> 5) & 0x1F) + 64) as u8 as char;
        let char3 = ((manufacturer_id & 0x1F) + 64) as u8 as char;
        format!("{}{}{}", char1, char2, char3)
    }

    fn extract_text_serial(&self, edid: &[u8]) -> Option<String> {
        if edid.len() < 128 {
            return None;
        }

        for i in (54..126).step_by(18) {
            if i + 17 < edid.len() {
                if edid[i] == 0x00
                    && edid[i + 1] == 0x00
                    && edid[i + 2] == 0x00
                    && edid[i + 3] == 0xFF
                {
                    let mut serial_bytes = Vec::new();
                    for j in 5..18 {
                        if i + j < edid.len() {
                            let byte = edid[i + j];
                            if byte == 0x00 || byte == 0x0A {
                                break;
                            }
                            if byte.is_ascii() && byte != 0x20 {
                                serial_bytes.push(byte);
                            }
                        }
                    }

                    if !serial_bytes.is_empty() {
                        let serial = String::from_utf8_lossy(&serial_bytes).trim().to_string();
                        if !serial.is_empty() {
                            return Some(serial);
                        }
                    }
                }
            }
        }

        None
    }

    pub fn list(&self) -> Result<()> {
        let monitors = self.enumerate_monitors()?;

        if monitors.is_empty() {
            println!("[!] No monitors with EDID found in registry");
            return Ok(());
        }

        println!("[*] Found {} monitor(s) with EDID data:", monitors.len());
        println!();

        for (i, monitor) in monitors.iter().enumerate() {
            println!("    Monitor #{}:", i + 1);
            println!("        Display ID:   {}", monitor.display_id);
            println!("        Device ID:    {}", monitor.device_id);
            println!("        Manufacturer: {}", monitor.manufacturer);
            println!("        Model:        {}", monitor.model);
            println!("        Serial (bin): {}", monitor.serial_number);
            if let Some(ref text_serial) = monitor.serial_text {
                println!("        Serial (txt): {}", text_serial);
            }
            println!(
                "        Manufacture:  Week {}, Year {}",
                monitor.week, monitor.year
            );
            if let Some(ref edid) = monitor.edid {
                println!("        EDID Size:    {} bytes", edid.len());
            }
            println!();
        }

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        let monitors = self.enumerate_monitors()?;

        if monitors.is_empty() {
            println!("[!] No monitors with EDID found to spoof");
            return Ok(());
        }

        let monitor_count = monitors.len();
        println!("[*] Spoofing {} monitor(s)...", monitor_count);

        let registry_hive = match RegistryHive::new(self.vmm) {
            Ok(hive) => hive,
            Err(e) => {
                println!("[!] Registry hive init failed: {}", e);
                return self.spoof_vfs(monitors);
            }
        };

        let system_hive = match registry_hive.find_system_hive() {
            Ok(hive) => {
                println!(
                    "[*] SYSTEM hive: {} (VA: 0x{:X}, Size: {})",
                    hive.name, hive.va, hive.size
                );
                hive
            }
            Err(e) => {
                println!("[!] SYSTEM hive not found: {}", e);
                return self.spoof_vfs(monitors);
            }
        };

        let navigator = CellNavigator::new(&registry_hive);

        if let Ok(root_cell) = navigator.get_root_cell(&system_hive) {
            println!("[*] Root cell at offset 0x{:X}", root_cell);
            if let Ok(root_key) = navigator.read_key_node(&system_hive, root_cell) {
                println!("[*] Root key name: '{}'", root_key.name);
                println!("[*] Subkey count: {}", root_key.subkey_count);
                if let Ok(subkeys) = navigator.enumerate_subkeys(&system_hive, &root_key) {
                    println!("[*] Found {} subkeys:", subkeys.len());
                    for (i, sk) in subkeys.iter().take(10).enumerate() {
                        println!("    [{}] {}", i, sk.name);
                    }
                }
            }
        }

        let mut spoofed_count = 0;

        for monitor in monitors {
            if let Some(ref original_edid) = monitor.edid {
                match self.generate_spoofed_edid(original_edid) {
                    Ok(spoofed_edid) => {
                        let registry_path = format!(
                            "ControlSet001\\Enum\\DISPLAY\\{}\\{}\\Device Parameters",
                            monitor.display_id, monitor.device_id
                        );

                        match self.write_edid_direct(
                            &navigator,
                            &system_hive,
                            &registry_path,
                            &spoofed_edid,
                        ) {
                            Ok(()) => {
                                spoofed_count += 1;
                                let new_serial = self
                                    .extract_text_serial(&spoofed_edid)
                                    .unwrap_or_else(|| "N/A".to_string());
                                println!(
                                    "    [+] {} ({}) - Serial: {} -> {}",
                                    monitor.display_id,
                                    monitor.manufacturer,
                                    monitor
                                        .serial_text
                                        .as_deref()
                                        .unwrap_or(&monitor.serial_number),
                                    new_serial
                                );
                            }
                            Err(e) => {
                                println!("    [!] Failed to spoof {}: {}", monitor.display_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "    [!] Failed to generate EDID for {}: {}",
                            monitor.display_id, e
                        );
                    }
                }
            }
        }

        println!();
        println!("[+] Spoofed {}/{} monitor(s)", spoofed_count, monitor_count);
        if spoofed_count > 0 {
            println!("[*] Changes written directly to registry hive memory");
        }

        Ok(())
    }

    fn write_edid_direct(
        &self,
        navigator: &CellNavigator,
        hive: &super::hive::HiveInfo,
        path: &str,
        edid: &[u8],
    ) -> Result<()> {
        let key = navigator.navigate_to_key(hive, path)?;
        let value = match navigator.find_value(hive, &key, "EDID")? {
            Some(v) => v,
            None => bail!("EDID value not found"),
        };

        let value_data = navigator.read_value_data(hive, &value)?;

        if edid.len() > value_data.data.len() {
            bail!(
                "Spoofed EDID ({} bytes) larger than original ({} bytes)",
                edid.len(),
                value_data.data.len()
            );
        }

        navigator.write_value_data(hive, &value_data, edid)?;

        Ok(())
    }

    fn spoof_vfs(&mut self, monitors: Vec<MonitorInfo>) -> Result<()> {
        let mut spoofed_count = 0;

        for monitor in &monitors {
            if let Some(ref original_edid) = monitor.edid {
                match self.generate_spoofed_edid(original_edid) {
                    Ok(spoofed_edid) => match self.write_edid_vfs(&monitor, &spoofed_edid) {
                        Ok(()) => {
                            spoofed_count += 1;
                            let new_serial = self
                                .extract_text_serial(&spoofed_edid)
                                .unwrap_or_else(|| "N/A".to_string());
                            println!(
                                "    [+] {} ({}) - Serial: {} -> {}",
                                monitor.display_id,
                                monitor.manufacturer,
                                monitor
                                    .serial_text
                                    .as_deref()
                                    .unwrap_or(&monitor.serial_number),
                                new_serial
                            );
                        }
                        Err(e) => {
                            println!("    [!] Failed to spoof {}: {}", monitor.display_id, e);
                        }
                    },
                    Err(e) => {
                        println!(
                            "    [!] Failed to generate EDID for {}: {}",
                            monitor.display_id, e
                        );
                    }
                }
            }
        }

        println!();
        println!(
            "[+] Spoofed {}/{} monitor(s) (VFS method)",
            spoofed_count,
            monitors.len()
        );
        println!("[!] VFS writes may not persist - verify with monitor check");

        Ok(())
    }

    fn write_edid_vfs(&self, monitor: &MonitorInfo, spoofed_edid: &[u8]) -> Result<()> {
        let edid_path = format!(
            "HKLM\\SYSTEM\\ControlSet001\\Enum\\DISPLAY\\{}\\{}\\Device Parameters\\EDID",
            monitor.display_id, monitor.device_id
        );

        let vfs_path = edid_path
            .replace("HKLM\\", "/registry/HKLM/")
            .replace("\\", "/");

        self.vmm.vfs_write(&vfs_path, spoofed_edid.to_vec(), 0);

        Ok(())
    }

    fn generate_spoofed_edid(&mut self, original_edid: &[u8]) -> Result<Vec<u8>> {
        if original_edid.len() < 128 {
            bail!("EDID data too short ({} bytes)", original_edid.len());
        }

        let mut spoofed = original_edid.to_vec();

        let new_serial: u32 = self.rng.gen();
        let serial_bytes = new_serial.to_le_bytes();
        spoofed[12] = serial_bytes[0];
        spoofed[13] = serial_bytes[1];
        spoofed[14] = serial_bytes[2];
        spoofed[15] = serial_bytes[3];

        let new_text_serial = self.generate_text_serial();
        self.update_text_serial(&mut spoofed, &new_text_serial);

        spoofed[16] = self.rng.gen_range(1..=53);

        let original_year = 1990 + (original_edid[17] as u16);
        let year_offset: i8 = self.rng.gen_range(-2..=2);
        let new_year = ((original_year as i32) + (year_offset as i32)).clamp(2015, 2025) as u16;
        spoofed[17] = (new_year - 1990) as u8;

        self.update_checksum(&mut spoofed);

        Ok(spoofed)
    }

    fn generate_text_serial(&mut self) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..10)
            .map(|_| {
                let idx = self.rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    fn update_text_serial(&self, edid: &mut [u8], new_serial: &str) {
        if edid.len() < 128 {
            return;
        }

        for i in (54..126).step_by(18) {
            if i + 17 < edid.len() {
                if edid[i] == 0x00
                    && edid[i + 1] == 0x00
                    && edid[i + 2] == 0x00
                    && edid[i + 3] == 0xFF
                {
                    for j in 5..18 {
                        if i + j < edid.len() {
                            edid[i + j] = 0x0A;
                        }
                    }

                    let serial_bytes = new_serial.as_bytes();
                    let copy_len = serial_bytes.len().min(13);
                    for (j, &byte) in serial_bytes.iter().take(copy_len).enumerate() {
                        if i + 5 + j < edid.len() {
                            edid[i + 5 + j] = byte;
                        }
                    }
                    return;
                }
            }
        }

        for i in (54..126).step_by(18) {
            if i + 17 < edid.len() {
                let is_empty = edid[i] == 0x00
                    && edid[i + 1] == 0x00
                    && edid[i + 2] == 0x00
                    && edid[i + 3] == 0x00;

                if is_empty {
                    edid[i] = 0x00;
                    edid[i + 1] = 0x00;
                    edid[i + 2] = 0x00;
                    edid[i + 3] = 0xFF;
                    edid[i + 4] = 0x00;

                    for j in 5..18 {
                        if i + j < edid.len() {
                            edid[i + j] = 0x0A;
                        }
                    }

                    let serial_bytes = new_serial.as_bytes();
                    let copy_len = serial_bytes.len().min(13);
                    for (j, &byte) in serial_bytes.iter().take(copy_len).enumerate() {
                        if i + 5 + j < edid.len() {
                            edid[i + 5 + j] = byte;
                        }
                    }
                    return;
                }
            }
        }
    }

    fn update_checksum(&self, edid: &mut [u8]) {
        if edid.len() < 128 {
            return;
        }

        let mut checksum: u8 = 0;
        for i in 0..127 {
            checksum = checksum.wrapping_add(edid[i]);
        }
        edid[127] = checksum.wrapping_neg();
    }

    pub fn list_hives(&self) -> Result<()> {
        let registry_hive = RegistryHive::new(self.vmm)?;
        registry_hive.list_hives()
    }

    pub fn restore(&self) -> Result<()> {
        let monitors = self.enumerate_monitors()?;

        if monitors.is_empty() {
            println!("[!] No monitors found");
            return Ok(());
        }

        println!(
            "[*] Checking {} monitor(s) for overrides...",
            monitors.len()
        );
        let mut override_count = 0;

        for monitor in monitors {
            let override_path = format!(
                "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\{}\\{}\\Device Parameters\\EDID_OVERRIDE",
                monitor.display_id, monitor.device_id
            );

            if self.vmm.reg_key(&override_path).is_ok() {
                println!(
                    "    [*] Found override for {} - manual deletion required",
                    monitor.display_id
                );
                override_count += 1;
            }
        }

        if override_count > 0 {
            println!();
            println!(
                "[*] Found {} override(s) - delete EDID_OVERRIDE keys and restart",
                override_count
            );
        } else {
            println!("[*] No EDID overrides found");
        }

        Ok(())
    }
}
