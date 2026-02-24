use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::core::Dma;
use crate::hwid::{SeedConfig, SerialGenerator};

use super::classpnp::ClassPnpSpoofer;
use super::nvme::NvmeSpoofer;
use super::offsets::{KERNEL_PID, NVME_IDENTIFY_SERIAL_SIZE};
use super::raid::RaidSpoofer;
use super::types::DiskDevice;

pub struct DiskSpoofer<'a> {
    dma: &'a Dma<'a>,
    nvme_spoofer: NvmeSpoofer<'a>,
    raid_spoofer: RaidSpoofer<'a>,
    classpnp_spoofer: Option<ClassPnpSpoofer<'a>>,
    devices: Vec<DiskDevice>,
}

impl<'a> DiskSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module = dma.get_module(KERNEL_PID, "storport.sys")?;
        println!(
            "[+] storport.sys @ 0x{:X} (size: 0x{:X})",
            module.base, module.size
        );

        let nvme_spoofer = NvmeSpoofer::new(dma);
        let raid_spoofer = RaidSpoofer::new(dma);

        let classpnp_spoofer = match ClassPnpSpoofer::new(dma) {
            Ok(s) => Some(s),
            Err(e) => {
                println!("[!] ClassPnp spoofer init failed: {}", e);
                None
            }
        };

        let mut spoofer = Self {
            dma,
            nvme_spoofer,
            raid_spoofer,
            classpnp_spoofer,
            devices: Vec::new(),
        };

        spoofer.enumerate_all()?;

        Ok(spoofer)
    }

    fn enumerate_all(&mut self) -> Result<()> {
        println!("\n[*] Enumerating via RAID_UNIT_EXTENSION method...");
        match self.raid_spoofer.enumerate() {
            Ok(raid_devices) => {
                for dev in raid_devices {
                    self.devices.push(DiskDevice::RaidUnit(dev));
                }
            }
            Err(e) => println!("[!] RAID enumeration failed: {}", e),
        }

        println!("\n[*] Enumerating via NVMe IdentifyController method...");
        match self.nvme_spoofer.enumerate() {
            Ok(nvme_devices) => {
                for dev in nvme_devices {
                    let already_found = self
                        .devices
                        .iter()
                        .any(|d| d.device_object() == dev.device_object);

                    if !already_found {
                        self.devices.push(DiskDevice::Nvme(dev));
                    }
                }
            }
            Err(e) => println!("[!] NVMe enumeration failed: {}", e),
        }

        if let Some(ref classpnp) = self.classpnp_spoofer {
            match classpnp.enumerate() {
                Ok(classpnp_devices) => {
                    for dev in classpnp_devices {
                        let already_found = self
                            .devices
                            .iter()
                            .any(|d| d.device_object() == dev.device_object);

                        if !already_found {
                            self.devices.push(DiskDevice::ClassPnp(dev));
                        }
                    }
                }
                Err(e) => println!("[!] ClassPnp enumeration failed: {}", e),
            }
        }

        Ok(())
    }

    pub fn list(&self) -> Result<()> {
        println!("\n[+] Disk Devices (Combined Methods):");

        if self.devices.is_empty() {
            println!("\n[!] No disk devices found");
            self.list_storage_drivers()?;
            return Ok(());
        }

        for (i, dev) in self.devices.iter().enumerate() {
            println!("\n    Device {} [{}]:", i, dev.type_name());

            match dev {
                DiskDevice::Nvme(nvme) => {
                    println!("        DeviceObject: 0x{:X}", nvme.device_object);
                    println!("        IdentifyData: 0x{:X}", nvme.identify_data_va);
                    println!("        Serial: {}", nvme.serial);
                    println!("        Model: {}", nvme.model);
                }
                DiskDevice::RaidUnit(raid) => {
                    println!("        DeviceObject: 0x{:X}", raid.device_object);
                    println!("        DeviceExtension: 0x{:X}", raid.device_extension);
                    println!("        SerialBufferPtr: 0x{:X}", raid.serial_buffer_ptr);
                    println!(
                        "        Serial: {} (len: {})",
                        raid.serial, raid.serial_length
                    );
                }
                DiskDevice::ClassPnp(classpnp) => {
                    println!("        DeviceObject: 0x{:X}", classpnp.device_object);
                    println!(
                        "        DeviceDescriptor: 0x{:X}",
                        classpnp.device_descriptor
                    );
                    println!("        SerialAddr: 0x{:X}", classpnp.serial_addr);
                    println!("        Serial: {}", classpnp.serial);
                    println!("        BusType: {}", classpnp.bus_type);
                }
            }
        }

        Ok(())
    }

    fn list_storage_drivers(&self) -> Result<()> {
        let drivers = self.dma.get_kernel_drivers()?;

        println!("\n    Storage-related drivers:");
        for driver in &drivers {
            let n = driver.name.to_lowercase();
            if n.contains("disk")
                || n.contains("stor")
                || n.contains("nvme")
                || n.contains("ahci")
                || n.contains("part")
                || n.contains("raid")
            {
                println!(
                    "        {} @ 0x{:X} (DevObj: 0x{:X})",
                    driver.name, driver.va, driver.device_object
                );
            }
        }

        Ok(())
    }

    pub fn spoof(&self) -> Result<()> {
        if self.devices.is_empty() {
            println!("[!] No disk devices to spoof");
            println!("[*] Run 'List Disk Info' first to discover devices");
            return Ok(());
        }

        let model = self.get_first_model();
        let new_serial = self.generate_serial(&model);
        let new_serial_str = String::from_utf8_lossy(&new_serial).to_string();
        println!("\n[*] New serial ({}): {}", model, new_serial_str.trim());

        for (i, dev) in self.devices.iter().enumerate() {
            println!("\n[*] Spoofing device {} [{}]...", i, dev.type_name());
            println!("    Old: {}", dev.serial());

            match dev {
                DiskDevice::Nvme(nvme) => {
                    self.nvme_spoofer.spoof_device(nvme, &new_serial)?;

                    let verify = self.nvme_spoofer.verify_serial(nvme)?;
                    println!("    New: {}", verify);
                }
                DiskDevice::RaidUnit(raid) => {
                    self.raid_spoofer.spoof_device(raid, &new_serial)?;

                    if let Err(e) = self.raid_spoofer.disable_smart(raid) {
                        println!("    [!] SMART disable failed: {}", e);
                    }

                    let verify = self.raid_spoofer.verify_serial(raid)?;
                    println!("    New: {}", verify);
                }
                DiskDevice::ClassPnp(classpnp) => {
                    if let Some(ref spoofer) = self.classpnp_spoofer {
                        spoofer.spoof_device(classpnp, &new_serial_str.trim())?;

                        let verify = spoofer.verify_serial(classpnp)?;
                        println!("    New: {}", verify);
                    }
                }
            }
        }

        println!("\n[+] Disk serial spoof complete!");
        println!("\n[!] RUN ON TARGET to refresh caches:");
        println!("    powershell -Command \"Update-StorageProviderCache -DiscoveryLevel Full\"");
        println!("\n[*] Verify with:");
        println!("    wmic diskdrive get serialnumber");
        println!("    powershell -Command \"Get-PhysicalDisk | Select SerialNumber\"");

        Ok(())
    }

    fn generate_serial(&self, model: &str) -> Vec<u8> {
        let seed_path = Path::new("hwid_seed.json");
        let config = SeedConfig::load(seed_path).unwrap_or_else(|| {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            SeedConfig::new(seed)
        });

        let mut generator = SerialGenerator::from_config(config);
        let serial_str = generator.generate_disk_serial(model);

        if let Err(e) = generator.to_config().save(seed_path) {
            println!("[!] Failed to save seed config: {}", e);
        }

        let mut serial = serial_str.into_bytes();
        serial.resize(NVME_IDENTIFY_SERIAL_SIZE, b' ');
        serial
    }

    fn get_first_model(&self) -> String {
        for dev in &self.devices {
            match dev {
                DiskDevice::Nvme(nvme) => return nvme.model.clone(),
                DiskDevice::RaidUnit(_) => return "RAID".to_string(),
                DiskDevice::ClassPnp(classpnp) => return classpnp.bus_type.to_string(),
            }
        }
        String::new()
    }
}
