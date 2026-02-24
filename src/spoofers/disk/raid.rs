use anyhow::{bail, Result};

use crate::core::Dma;

use super::offsets::{
    DEVICE_OBJECT_DEVICE_EXTENSION, DEVICE_OBJECT_DEVICE_TYPE, DEVICE_OBJECT_NEXT_DEVICE,
    FILE_DEVICE_DISK, KERNEL_PID, RAID_UNIT_SERIAL_DIRECT_OFFSET, RAID_UNIT_SERIAL_STRING_OFFSET,
    RAID_UNIT_SMART_MASK_OFFSET, STRING_BUFFER_OFFSET, STRING_LENGTH_OFFSET,
};
use super::types::RaidUnitDevice;

pub struct RaidSpoofer<'a> {
    dma: &'a Dma<'a>,
}

impl<'a> RaidSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Self {
        Self { dma }
    }

    pub fn enumerate(&self) -> Result<Vec<RaidUnitDevice>> {
        let mut devices = Vec::new();

        let drivers = self.dma.get_kernel_drivers()?;

        for driver in &drivers {
            let name_lower = driver.name.to_lowercase();
            if name_lower.contains("storahci") || name_lower.contains("stornvme") {
                if driver.device_object != 0 {
                    println!(
                        "[*] Scanning {} device chain @ 0x{:X}",
                        driver.name, driver.device_object
                    );
                    self.walk_raid_chain(driver.device_object, &mut devices)?;
                }
            }
        }

        Ok(devices)
    }

    fn walk_raid_chain(&self, first_device: u64, devices: &mut Vec<RaidUnitDevice>) -> Result<()> {
        let mut device_ptr = first_device;
        let mut count = 0;

        while device_ptr != 0 && count < 64 {
            if let Ok(dev) = self.try_read_raid_unit(device_ptr) {
                let already_found = devices
                    .iter()
                    .any(|d| d.device_extension == dev.device_extension);

                if !already_found {
                    devices.push(dev);
                }
            }

            device_ptr = match self
                .dma
                .read_u64(KERNEL_PID, device_ptr + DEVICE_OBJECT_NEXT_DEVICE)
            {
                Ok(ptr) => ptr,
                Err(_) => break,
            };
            count += 1;
        }

        Ok(())
    }

    fn try_read_raid_unit(&self, device_object: u64) -> Result<RaidUnitDevice> {
        let device_type = self
            .dma
            .read_u32(KERNEL_PID, device_object + DEVICE_OBJECT_DEVICE_TYPE)?;

        if device_type != FILE_DEVICE_DISK {
            bail!("Not a disk device");
        }

        let dev_ext = self
            .dma
            .read_u64(KERNEL_PID, device_object + DEVICE_OBJECT_DEVICE_EXTENSION)?;

        if dev_ext == 0 || dev_ext < 0xFFFF800000000000 {
            bail!("Invalid device extension");
        }

        let serial_string_addr = dev_ext + RAID_UNIT_SERIAL_STRING_OFFSET;
        let serial_length = self
            .dma
            .read_u64(KERNEL_PID, serial_string_addr + STRING_LENGTH_OFFSET)?
            as u16
            & 0xFFFF;

        if serial_length == 0 || serial_length > 256 {
            bail!("Invalid serial length");
        }

        let serial_buffer_ptr = self
            .dma
            .read_u64(KERNEL_PID, serial_string_addr + STRING_BUFFER_OFFSET)?;

        let serial = if serial_buffer_ptr >= 0xFFFF800000000000 {
            let serial_bytes =
                self.dma
                    .read(KERNEL_PID, serial_buffer_ptr, serial_length as usize)?;
            String::from_utf8_lossy(&serial_bytes).trim().to_string()
        } else {
            let serial_direct_addr = dev_ext + RAID_UNIT_SERIAL_DIRECT_OFFSET;
            let serial_bytes =
                self.dma
                    .read(KERNEL_PID, serial_direct_addr, serial_length as usize)?;
            String::from_utf8_lossy(&serial_bytes).trim().to_string()
        };

        if serial.is_empty() || !serial.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            bail!("Invalid serial format");
        }

        let serial_direct_addr = dev_ext + RAID_UNIT_SERIAL_DIRECT_OFFSET;
        let smart_mask_addr = dev_ext + RAID_UNIT_SMART_MASK_OFFSET;

        println!("[+] Found RAID device:");
        println!("    DeviceObject: 0x{:X}", device_object);
        println!("    DeviceExtension: 0x{:X}", dev_ext);
        println!("    Serial: {} (len: {})", serial, serial_length);

        Ok(RaidUnitDevice {
            device_object,
            device_extension: dev_ext,
            serial_buffer_ptr,
            serial_direct_addr,
            smart_mask_addr,
            serial,
            serial_length,
        })
    }

    pub fn spoof_device(&self, device: &RaidUnitDevice, new_serial: &[u8]) -> Result<()> {
        let write_len = new_serial.len().min(device.serial_length as usize);
        let mut padded_serial = vec![0x20u8; device.serial_length as usize];
        padded_serial[..write_len].copy_from_slice(&new_serial[..write_len]);

        if device.serial_buffer_ptr >= 0xFFFF800000000000 {
            self.dma
                .write(KERNEL_PID, device.serial_buffer_ptr, &padded_serial)?;
            println!(
                "    [+] Patched serial buffer @ 0x{:X}",
                device.serial_buffer_ptr
            );
        }

        self.dma
            .write(KERNEL_PID, device.serial_direct_addr, &padded_serial)?;
        println!(
            "    [+] Patched direct serial @ 0x{:X}",
            device.serial_direct_addr
        );

        Ok(())
    }

    pub fn disable_smart(&self, device: &RaidUnitDevice) -> Result<()> {
        let zero_mask: [u8; 4] = [0, 0, 0, 0];
        self.dma
            .write(KERNEL_PID, device.smart_mask_addr, &zero_mask)?;
        println!("    [+] Disabled SMART @ 0x{:X}", device.smart_mask_addr);
        Ok(())
    }

    pub fn verify_serial(&self, device: &RaidUnitDevice) -> Result<String> {
        let addr = if device.serial_buffer_ptr >= 0xFFFF800000000000 {
            device.serial_buffer_ptr
        } else {
            device.serial_direct_addr
        };

        let serial_bytes = self
            .dma
            .read(KERNEL_PID, addr, device.serial_length as usize)?;
        Ok(String::from_utf8_lossy(&serial_bytes).trim().to_string())
    }
}
