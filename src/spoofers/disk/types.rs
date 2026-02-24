#[derive(Debug, Clone)]
pub struct NvmeDevice {
    pub device_object: u64,
    pub identify_data_va: u64,
    pub serial: String,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct RaidUnitDevice {
    pub device_object: u64,
    pub device_extension: u64,
    pub serial_buffer_ptr: u64,
    pub serial_direct_addr: u64,
    pub smart_mask_addr: u64,
    pub serial: String,
    pub serial_length: u16,
}

#[derive(Debug, Clone)]
pub struct ClassPnpDevice {
    pub device_object: u64,
    pub device_extension: u64,
    pub device_descriptor: u64,
    pub serial_offset: u32,
    pub serial_addr: u64,
    pub serial: String,
    pub bus_type: u32,
}

#[derive(Debug, Clone)]
pub enum DiskDevice {
    Nvme(NvmeDevice),
    RaidUnit(RaidUnitDevice),
    ClassPnp(ClassPnpDevice),
}

impl DiskDevice {
    pub fn serial(&self) -> &str {
        match self {
            DiskDevice::Nvme(dev) => &dev.serial,
            DiskDevice::RaidUnit(dev) => &dev.serial,
            DiskDevice::ClassPnp(dev) => &dev.serial,
        }
    }

    pub fn device_object(&self) -> u64 {
        match self {
            DiskDevice::Nvme(dev) => dev.device_object,
            DiskDevice::RaidUnit(dev) => dev.device_object,
            DiskDevice::ClassPnp(dev) => dev.device_object,
        }
    }

    pub fn type_name(&self) -> &str {
        match self {
            DiskDevice::Nvme(_) => "NVMe",
            DiskDevice::RaidUnit(_) => "RAID",
            DiskDevice::ClassPnp(_) => "ClassPnp",
        }
    }
}
