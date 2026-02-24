use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::core::Dma;
use crate::hwid::{SeedConfig, SerialGenerator};

use super::offsets::*;
use super::types::{MountedDevice, VolumeGuid};

const KERNEL_PID: u32 = 4;

pub struct VolumeSpoofer<'a> {
    dma: &'a Dma<'a>,
    mountmgr_base: u64,
    device_extension: u64,
    mounted_devices: Vec<MountedDevice>,
}

impl<'a> VolumeSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module = dma.get_module(KERNEL_PID, "mountmgr.sys")?;
        println!(
            "[+] mountmgr.sys @ 0x{:X} (size: 0x{:X})",
            module.base, module.size
        );

        let gdevice_object_ptr = module.base + MOUNTMGR_GDEVICE_OBJECT;
        let device_object = dma.read_u64(KERNEL_PID, gdevice_object_ptr)?;

        if device_object == 0 || device_object < 0xFFFF000000000000 {
            return Err(anyhow::anyhow!(
                "Invalid gDeviceObject: 0x{:X}",
                device_object
            ));
        }
        println!("[+] gDeviceObject @ 0x{:X}", device_object);

        let device_extension =
            dma.read_u64(KERNEL_PID, device_object + DEVICE_OBJECT_DEVICE_EXTENSION)?;
        if device_extension == 0 || device_extension < 0xFFFF000000000000 {
            return Err(anyhow::anyhow!(
                "Invalid DeviceExtension: 0x{:X}",
                device_extension
            ));
        }
        println!("[+] DeviceExtension @ 0x{:X}", device_extension);

        let mut spoofer = Self {
            dma,
            mountmgr_base: module.base,
            device_extension,
            mounted_devices: Vec::new(),
        };

        spoofer.enumerate()?;

        Ok(spoofer)
    }

    fn enumerate(&mut self) -> Result<()> {
        self.mounted_devices.clear();

        let list_head = self.device_extension + EXTENSION_MOUNTED_DEVICES_LIST;
        let first_entry = self
            .dma
            .read_u64(KERNEL_PID, list_head + LIST_ENTRY_FLINK)?;

        if first_entry == 0 || first_entry == list_head {
            println!("[!] Mounted devices list is empty");
            return Ok(());
        }

        let mut current = first_entry;
        let mut count = 0;
        let max_entries = 256;

        while current != list_head && count < max_entries {
            if current == 0 || current < 0xFFFF000000000000 {
                break;
            }

            match self.read_mounted_device(current) {
                Ok(mut device) => {
                    self.enumerate_symbolic_links(&mut device)?;
                    self.mounted_devices.push(device);
                }
                Err(e) => {
                    println!("[!] Failed to read device @ 0x{:X}: {}", current, e);
                }
            }

            let next = self.dma.read_u64(KERNEL_PID, current + LIST_ENTRY_FLINK)?;
            if next == current {
                break;
            }
            current = next;
            count += 1;
        }

        Ok(())
    }

    fn read_mounted_device(&self, entry_addr: u64) -> Result<MountedDevice> {
        let device_name_addr = entry_addr + MOUNTED_DEVICE_DEVICE_NAME;
        let device_name = self.read_unicode_string(device_name_addr)?;

        let unique_id_ptr = self
            .dma
            .read_u64(KERNEL_PID, entry_addr + MOUNTED_DEVICE_UNIQUE_ID)?;
        let unique_id = if unique_id_ptr != 0 && unique_id_ptr > 0xFFFF000000000000 {
            let id_len = self.dma.read_u16(KERNEL_PID, unique_id_ptr)?;
            if id_len > 0 && id_len < 256 {
                let id_buf_ptr = self.dma.read_u64(KERNEL_PID, unique_id_ptr + 8)?;
                if id_buf_ptr != 0 {
                    self.dma
                        .read(KERNEL_PID, id_buf_ptr, id_len as usize)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(MountedDevice::new(entry_addr, device_name, unique_id))
    }

    fn enumerate_symbolic_links(&self, device: &mut MountedDevice) -> Result<()> {
        let list_head = device.entry_addr + MOUNTED_DEVICE_SYMBOLIC_LINKS;
        let first_entry = self
            .dma
            .read_u64(KERNEL_PID, list_head + LIST_ENTRY_FLINK)?;

        if first_entry == 0 || first_entry == list_head {
            return Ok(());
        }

        let mut current = first_entry;
        let mut count = 0;
        let max_entries = 64;

        while current != list_head && count < max_entries {
            if current == 0 || current < 0xFFFF000000000000 {
                break;
            }

            match self.read_symbolic_link(current) {
                Ok(Some(guid)) => {
                    device.add_volume_guid(guid);
                }
                Ok(None) => {}
                Err(_) => {}
            }

            let next = self.dma.read_u64(KERNEL_PID, current + LIST_ENTRY_FLINK)?;
            if next == current {
                break;
            }
            current = next;
            count += 1;
        }

        Ok(())
    }

    fn read_symbolic_link(&self, entry_addr: u64) -> Result<Option<VolumeGuid>> {
        let is_active = self
            .dma
            .read_u8(KERNEL_PID, entry_addr + SYMBOLIC_LINK_IS_ACTIVE)?;

        let name_addr = entry_addr + SYMBOLIC_LINK_NAME;
        let name_len = self
            .dma
            .read_u16(KERNEL_PID, name_addr + UNICODE_STRING_LENGTH)?;
        let name_buf = self
            .dma
            .read_u64(KERNEL_PID, name_addr + UNICODE_STRING_BUFFER)?;

        if name_len == 0 || name_buf == 0 || name_buf < 0xFFFF000000000000 {
            return Ok(None);
        }

        let name_bytes = self.dma.read(KERNEL_PID, name_buf, name_len as usize)?;
        let full_path = String::from_utf16_lossy(
            &name_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect::<Vec<_>>(),
        );

        if !full_path.starts_with(VOLUME_GUID_PREFIX) {
            return Ok(None);
        }

        let guid_start = VOLUME_GUID_START_OFFSET;
        let guid_end = guid_start + VOLUME_GUID_CHAR_COUNT;

        if full_path.len() >= guid_end {
            let guid = full_path[guid_start..guid_end].to_string();
            return Ok(Some(VolumeGuid::new(
                entry_addr,
                name_buf,
                guid,
                full_path,
                is_active != 0,
            )));
        }

        Ok(None)
    }

    fn read_unicode_string(&self, addr: u64) -> Result<String> {
        let length = self
            .dma
            .read_u16(KERNEL_PID, addr + UNICODE_STRING_LENGTH)?;
        let buffer = self
            .dma
            .read_u64(KERNEL_PID, addr + UNICODE_STRING_BUFFER)?;

        if length == 0 || buffer == 0 || buffer < 0xFFFF000000000000 {
            return Ok(String::new());
        }

        let bytes = self.dma.read(KERNEL_PID, buffer, length as usize)?;
        let utf16: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect();

        Ok(String::from_utf16_lossy(&utf16))
    }

    pub fn list(&self) -> Result<()> {
        println!("\n[+] Volume GUIDs:");

        if self.mounted_devices.is_empty() {
            println!("    No mounted devices found");
            return Ok(());
        }

        let mut guid_count = 0;

        for device in &self.mounted_devices {
            if device.volume_guids.is_empty() {
                continue;
            }

            println!("\n    Device: {}", device.device_name);

            for guid in &device.volume_guids {
                let status = if guid.is_active { "active" } else { "inactive" };
                println!("        [{}] {}", status, guid.guid);
                println!("            Path: {}", guid.full_path);
                println!("            BufferAddr: 0x{:X}", guid.name_buffer_addr);
                guid_count += 1;
            }
        }

        if guid_count == 0 {
            println!("    No volume GUIDs found");
        } else {
            println!("\n    Total: {} volume GUIDs", guid_count);
        }

        Ok(())
    }

    pub fn spoof(&self) -> Result<()> {
        let seed_path = Path::new("hwid_seed.json");
        let config = SeedConfig::load(seed_path).unwrap_or_else(|| {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            SeedConfig::new(seed)
        });

        let mut generator = SerialGenerator::from_config(config);
        let mut spoofed_count = 0;

        println!("\n[*] Spoofing volume GUIDs...");

        for device in &self.mounted_devices {
            for guid in &device.volume_guids {
                let new_guid_full = generator.generate_guid();
                let new_guid = new_guid_full
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .to_lowercase();
                println!("\n    Old: {}", guid.guid);
                println!("    New: {}", new_guid);

                match self.spoof_guid(guid, &new_guid) {
                    Ok(()) => {
                        spoofed_count += 1;
                        println!("    Status: OK");
                    }
                    Err(e) => {
                        println!("    Status: FAILED - {}", e);
                    }
                }
            }
        }

        if let Err(e) = generator.to_config().save(seed_path) {
            println!("[!] Failed to save seed config: {}", e);
        }

        if spoofed_count == 0 {
            println!("\n[!] No volume GUIDs were spoofed");
        } else {
            println!("\n[+] Spoofed {} volume GUIDs", spoofed_count);
            println!("\n[!] Note: Registry values in HKLM\\SYSTEM\\MountedDevices are NOT patched");
            println!("    These are persistent and may need separate handling");
        }

        Ok(())
    }

    fn spoof_guid(&self, guid: &VolumeGuid, new_guid: &str) -> Result<()> {
        if new_guid.len() != VOLUME_GUID_CHAR_COUNT {
            return Err(anyhow::anyhow!(
                "Invalid GUID length: {} (expected {})",
                new_guid.len(),
                VOLUME_GUID_CHAR_COUNT
            ));
        }

        let guid_offset = VOLUME_GUID_START_OFFSET * 2;
        let write_addr = guid.name_buffer_addr + guid_offset as u64;

        let new_guid_utf16: Vec<u8> = new_guid
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        self.dma.write(KERNEL_PID, write_addr, &new_guid_utf16)?;

        let verify = self
            .dma
            .read(KERNEL_PID, write_addr, new_guid_utf16.len())?;
        if verify != new_guid_utf16 {
            return Err(anyhow::anyhow!("Verification failed"));
        }

        Ok(())
    }

    pub fn refresh(&mut self) -> Result<()> {
        println!("[*] Refreshing volume list...");
        self.enumerate()?;
        println!("[+] Found {} mounted devices", self.mounted_devices.len());
        Ok(())
    }

    pub fn volume_count(&self) -> usize {
        self.mounted_devices
            .iter()
            .map(|d| d.volume_guids.len())
            .sum()
    }
}
