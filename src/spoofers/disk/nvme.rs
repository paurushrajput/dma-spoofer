use anyhow::Result;

use crate::core::Dma;

use super::offsets::{
    DEVICE_OBJECT_DEVICE_EXTENSION, DEVICE_OBJECT_NEXT_DEVICE, KERNEL_PID,
    NVME_IDENTIFY_MODEL_OFFSET, NVME_IDENTIFY_MODEL_SIZE, NVME_IDENTIFY_SERIAL_OFFSET,
    NVME_IDENTIFY_SERIAL_SIZE, NVME_VENDOR_IDS,
};
use super::types::NvmeDevice;

pub struct NvmeSpoofer<'a> {
    dma: &'a Dma<'a>,
}

impl<'a> NvmeSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Self {
        Self { dma }
    }

    pub fn enumerate(&self) -> Result<Vec<NvmeDevice>> {
        let mut devices = Vec::new();
        let drivers = self.dma.get_kernel_drivers()?;

        for driver in &drivers {
            let name_lower = driver.name.to_lowercase();
            if name_lower.contains("stornvme") {
                if driver.device_object != 0 {
                    println!("[*] Scanning stornvme chain @ 0x{:X}", driver.device_object);
                    self.walk_nvme_chain(driver.device_object, &mut devices)?;
                }
            }
        }

        for driver in &drivers {
            let name_lower = driver.name.to_lowercase();
            if name_lower.ends_with("\\disk") || name_lower == "disk" {
                if driver.device_object != 0 {
                    println!("[*] Scanning disk chain @ 0x{:X}", driver.device_object);
                    self.walk_nvme_chain(driver.device_object, &mut devices)?;
                }
            }
        }

        Ok(devices)
    }

    fn walk_nvme_chain(&self, first_device: u64, devices: &mut Vec<NvmeDevice>) -> Result<()> {
        let mut device_ptr = first_device;
        let mut count = 0;

        while device_ptr != 0 && count < 64 {
            if let Some(dev) = self.try_find_identify_data(device_ptr)? {
                let already_found = devices
                    .iter()
                    .any(|d| d.identify_data_va == dev.identify_data_va);

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

    fn try_find_identify_data(&self, device_object: u64) -> Result<Option<NvmeDevice>> {
        let dev_ext = self
            .dma
            .read_u64(KERNEL_PID, device_object + DEVICE_OBJECT_DEVICE_EXTENSION)?;

        if dev_ext == 0 || dev_ext < 0xFFFF800000000000 {
            return Ok(None);
        }

        let ext_data = match self.dma.read(KERNEL_PID, dev_ext, 0x800) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };

        for offset in (0..0x700).step_by(8) {
            let ptr = u64::from_le_bytes(ext_data[offset..offset + 8].try_into()?);

            if ptr < 0xFFFF800000000000 {
                continue;
            }

            if let Some(dev) = self.try_read_identify_at(device_object, ptr)? {
                return Ok(Some(dev));
            }

            if let Ok(inner_ptr) = self.dma.read_u64(KERNEL_PID, ptr) {
                if inner_ptr >= 0xFFFF800000000000 {
                    if let Some(dev) = self.try_read_identify_at(device_object, inner_ptr)? {
                        return Ok(Some(dev));
                    }
                }
            }

            for ctrl_offset in &[0x250u64, 0x248, 0x258, 0x240] {
                if let Ok(identify_ptr) = self.dma.read_u64(KERNEL_PID, ptr + ctrl_offset) {
                    if identify_ptr >= 0xFFFF800000000000 {
                        if let Some(dev) = self.try_read_identify_at(device_object, identify_ptr)? {
                            return Ok(Some(dev));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn try_read_identify_at(&self, device_object: u64, addr: u64) -> Result<Option<NvmeDevice>> {
        let header = match self.dma.read(KERNEL_PID, addr, 0x50) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };

        let vid = u16::from_le_bytes([header[0], header[1]]);

        if !NVME_VENDOR_IDS.contains(&vid) && vid != 0 {
            if vid < 0x1000 {
                return Ok(None);
            }
        }

        let serial_start = NVME_IDENTIFY_SERIAL_OFFSET as usize;
        let serial_end = serial_start + NVME_IDENTIFY_SERIAL_SIZE;
        let serial_bytes = &header[serial_start..serial_end];
        let serial = String::from_utf8_lossy(serial_bytes).trim().to_string();

        if serial.is_empty() || serial.chars().all(|c| c == '\0' || c == ' ') {
            return Ok(None);
        }

        if !serial.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Ok(None);
        }

        let model_start = NVME_IDENTIFY_MODEL_OFFSET as usize;
        let model_end = model_start + NVME_IDENTIFY_MODEL_SIZE;
        let model_bytes = &header[model_start..model_end];
        let model = String::from_utf8_lossy(model_bytes).trim().to_string();

        if model.is_empty() || !model.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Ok(None);
        }

        println!("[+] Found NVMe IdentifyControllerData:");
        println!("    DeviceObject: 0x{:X}", device_object);
        println!("    IdentifyData @ 0x{:X}", addr);
        println!("    VID: 0x{:04X}", vid);
        println!("    Serial: {}", serial);
        println!("    Model: {}", model);

        Ok(Some(NvmeDevice {
            device_object,
            identify_data_va: addr,
            serial,
            model,
        }))
    }

    pub fn spoof_device(&self, device: &NvmeDevice, new_serial: &[u8]) -> Result<()> {
        let serial_addr = device.identify_data_va + NVME_IDENTIFY_SERIAL_OFFSET;

        let mut padded = vec![0x20u8; NVME_IDENTIFY_SERIAL_SIZE];
        let copy_len = new_serial.len().min(NVME_IDENTIFY_SERIAL_SIZE);
        padded[..copy_len].copy_from_slice(&new_serial[..copy_len]);

        let swapped = Self::byte_swap_pairs(&padded);

        self.dma.write(KERNEL_PID, serial_addr, &swapped)?;
        println!("    [+] Patched NVMe serial @ 0x{:X}", serial_addr);

        Ok(())
    }

    fn byte_swap_pairs(data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        for i in (0..result.len()).step_by(2) {
            if i + 1 < result.len() {
                result.swap(i, i + 1);
            }
        }
        result
    }

    pub fn verify_serial(&self, device: &NvmeDevice) -> Result<String> {
        let serial_addr = device.identify_data_va + NVME_IDENTIFY_SERIAL_OFFSET;
        let serial_bytes = self
            .dma
            .read(KERNEL_PID, serial_addr, NVME_IDENTIFY_SERIAL_SIZE)?;
        Ok(String::from_utf8_lossy(&serial_bytes).trim().to_string())
    }
}
