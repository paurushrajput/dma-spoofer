use anyhow::{anyhow, Result};

use super::offsets::{
    DEVICE_OBJECT_DEVICE_EXTENSION, DEVICE_OBJECT_NEXT_DEVICE, FDO_DEVICE_DESCRIPTOR_OFFSET,
    KERNEL_PID, STORAGE_DESCRIPTOR_BUS_TYPE_OFFSET, STORAGE_DESCRIPTOR_SERIAL_OFFSET_OFFSET,
    STORAGE_DESCRIPTOR_SIZE_OFFSET, STORAGE_DESCRIPTOR_VERSION_OFFSET,
};
use super::types::ClassPnpDevice;
use crate::core::Dma;

pub struct ClassPnpSpoofer<'a> {
    dma: &'a Dma<'a>,
    disk_device_object: u64,
}

impl<'a> ClassPnpSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let drivers = dma.get_kernel_drivers()?;

        let disk_driver = drivers
            .iter()
            .find(|d| {
                let name = d.name.to_lowercase();
                name == "disk.sys" || name == "disk"
            })
            .ok_or_else(|| anyhow!("disk.sys not found"))?;

        println!(
            "[+] disk.sys @ {:#X} (DevObj: {:#X})",
            disk_driver.va, disk_driver.device_object
        );

        Ok(Self {
            dma,
            disk_device_object: disk_driver.device_object,
        })
    }

    pub fn enumerate(&self) -> Result<Vec<ClassPnpDevice>> {
        let mut devices = Vec::new();

        println!("\n[*] Enumerating via disk.sys FUNCTIONAL_DEVICE_EXTENSION...");

        if self.disk_device_object != 0 {
            println!(
                "[*] Scanning disk device chain @ {:#X}",
                self.disk_device_object
            );
            self.walk_disk_chain(self.disk_device_object, &mut devices)?;
        }

        Ok(devices)
    }

    fn walk_disk_chain(&self, start_device: u64, devices: &mut Vec<ClassPnpDevice>) -> Result<()> {
        let mut current = start_device;
        let mut visited = std::collections::HashSet::new();

        while current != 0 && !visited.contains(&current) {
            visited.insert(current);

            if let Some(device) = self.try_read_fdo_extension(current)? {
                devices.push(device);
            }

            current = self
                .dma
                .read_u64(KERNEL_PID, current + DEVICE_OBJECT_NEXT_DEVICE)?;
        }

        Ok(())
    }

    fn try_read_fdo_extension(&self, device_object: u64) -> Result<Option<ClassPnpDevice>> {
        let dev_ext = self
            .dma
            .read_u64(KERNEL_PID, device_object + DEVICE_OBJECT_DEVICE_EXTENSION)?;
        if dev_ext == 0 || !self.is_valid_kernel_ptr(dev_ext) {
            return Ok(None);
        }

        let device_descriptor = self
            .dma
            .read_u64(KERNEL_PID, dev_ext + FDO_DEVICE_DESCRIPTOR_OFFSET)?;
        if device_descriptor == 0 || !self.is_valid_kernel_ptr(device_descriptor) {
            return Ok(None);
        }

        let version = self.dma.read_u32(
            KERNEL_PID,
            device_descriptor + STORAGE_DESCRIPTOR_VERSION_OFFSET,
        )?;
        let size = self.dma.read_u32(
            KERNEL_PID,
            device_descriptor + STORAGE_DESCRIPTOR_SIZE_OFFSET,
        )?;

        if version == 0 || size < 0x28 || size > 0x1000 {
            return Ok(None);
        }

        let serial_offset = self.dma.read_u32(
            KERNEL_PID,
            device_descriptor + STORAGE_DESCRIPTOR_SERIAL_OFFSET_OFFSET,
        )?;
        if serial_offset == 0 || serial_offset >= size {
            return Ok(None);
        }

        let bus_type = self.dma.read_u32(
            KERNEL_PID,
            device_descriptor + STORAGE_DESCRIPTOR_BUS_TYPE_OFFSET,
        )?;

        let serial_addr = device_descriptor + serial_offset as u64;
        let serial = self.read_null_terminated_string(serial_addr, 64)?;

        if serial.is_empty() || !self.is_valid_serial(&serial) {
            return Ok(None);
        }

        println!("[+] Found disk.sys device:");
        println!("    DeviceObject: {:#X}", device_object);
        println!("    DeviceExtension: {:#X}", dev_ext);
        println!("    DeviceDescriptor: {:#X}", device_descriptor);
        println!("    SerialOffset: {:#X}", serial_offset);
        println!("    Serial: {}", serial);
        println!("    BusType: {}", self.bus_type_name(bus_type));

        Ok(Some(ClassPnpDevice {
            device_object,
            device_extension: dev_ext,
            device_descriptor,
            serial_offset,
            serial_addr,
            serial,
            bus_type,
        }))
    }

    pub fn spoof_device(&self, device: &ClassPnpDevice, new_serial: &str) -> Result<()> {
        let serial_bytes = new_serial.as_bytes();
        let mut buffer = vec![0u8; serial_bytes.len() + 1];
        buffer[..serial_bytes.len()].copy_from_slice(serial_bytes);

        self.dma.write(KERNEL_PID, device.serial_addr, &buffer)?;
        println!(
            "    [+] Patched ClassPnp serial @ {:#X}",
            device.serial_addr
        );

        Ok(())
    }

    pub fn verify_serial(&self, device: &ClassPnpDevice) -> Result<String> {
        self.read_null_terminated_string(device.serial_addr, 64)
    }

    fn read_null_terminated_string(&self, addr: u64, max_len: usize) -> Result<String> {
        let buffer = self.dma.read(KERNEL_PID, addr, max_len)?;

        let end = buffer.iter().position(|&b| b == 0).unwrap_or(max_len);
        let s = String::from_utf8_lossy(&buffer[..end]).to_string();

        Ok(s.trim().to_string())
    }

    fn is_valid_kernel_ptr(&self, ptr: u64) -> bool {
        ptr >= 0xFFFF800000000000 && ptr < 0xFFFFFFFFFFFFFFFF
    }

    fn is_valid_serial(&self, serial: &str) -> bool {
        if serial.len() < 4 || serial.len() > 64 {
            return false;
        }

        serial
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ' ')
    }

    fn bus_type_name(&self, bus_type: u32) -> &'static str {
        match bus_type {
            0x00 => "Unknown",
            0x01 => "SCSI",
            0x02 => "ATAPI",
            0x03 => "ATA",
            0x04 => "1394",
            0x05 => "SSA",
            0x06 => "Fibre",
            0x07 => "USB",
            0x08 => "RAID",
            0x09 => "iSCSI",
            0x0A => "SAS",
            0x0B => "SATA",
            0x0C => "SD",
            0x0D => "MMC",
            0x0E => "Virtual",
            0x0F => "FileBackedVirtual",
            0x10 => "Spaces",
            0x11 => "NVMe",
            0x12 => "SCM",
            0x13 => "UFS",
            _ => "Unknown",
        }
    }
}
