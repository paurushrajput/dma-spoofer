use anyhow::Result;
use memprocfs::{LeechCore, Vmm, FLAG_NOCACHE};

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct KernelDriver {
    pub va: u64,
    pub device_object: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FpgaInfo {
    pub id: u64,
    pub version_major: u64,
    pub version_minor: u64,
}

pub struct Dma<'a> {
    vmm: Vmm<'a>,
}

impl<'a> Dma<'a> {
    pub fn new() -> Result<Self> {
        println!("    Loading vmm.dll...");

        let args = vec!["-device", "fpga", "-waitinitialize"];

        println!("    Connecting to FPGA...");
        let vmm = Vmm::new("vmm.dll", &args)
            .map_err(|e| anyhow::anyhow!("VMMDLL_Initialize failed: {}", e))?;

        Ok(Self { vmm })
    }

    pub fn vmm(&self) -> &Vmm<'a> {
        &self.vmm
    }

    pub fn read(&self, pid: u32, addr: u64, size: usize) -> Result<Vec<u8>> {
        let process = self
            .vmm
            .process_from_pid(pid)
            .map_err(|e| anyhow::anyhow!("Failed to get process {}: {}", pid, e))?;

        process
            .mem_read_ex(addr, size, FLAG_NOCACHE)
            .map_err(|e| anyhow::anyhow!("Read failed at 0x{:X}: {}", addr, e))
    }

    pub fn write(&self, pid: u32, addr: u64, data: &[u8]) -> Result<()> {
        let process = self
            .vmm
            .process_from_pid(pid)
            .map_err(|e| anyhow::anyhow!("Failed to get process {}: {}", pid, e))?;

        process
            .mem_write(addr, data)
            .map_err(|e| anyhow::anyhow!("Write failed at 0x{:X}: {}", addr, e))
    }

    pub fn read_phys(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.vmm
            .mem_read_ex(addr, size, FLAG_NOCACHE)
            .map_err(|e| anyhow::anyhow!("Physical read failed at 0x{:X}: {}", addr, e))
    }

    pub fn write_phys(&self, addr: u64, data: &[u8]) -> Result<()> {
        self.vmm
            .mem_write(addr, data)
            .map_err(|e| anyhow::anyhow!("Physical write failed at 0x{:X}: {}", addr, e))
    }

    pub fn read_u8(&self, pid: u32, addr: u64) -> Result<u8> {
        let buf = self.read(pid, addr, 1)?;
        Ok(buf[0])
    }

    pub fn read_u16(&self, pid: u32, addr: u64) -> Result<u16> {
        let buf = self.read(pid, addr, 2)?;
        Ok(u16::from_le_bytes(buf[..2].try_into()?))
    }

    pub fn read_u32(&self, pid: u32, addr: u64) -> Result<u32> {
        let buf = self.read(pid, addr, 4)?;
        Ok(u32::from_le_bytes(buf[..4].try_into()?))
    }

    pub fn read_u64(&self, pid: u32, addr: u64) -> Result<u64> {
        let buf = self.read(pid, addr, 8)?;
        Ok(u64::from_le_bytes(buf[..8].try_into()?))
    }

    pub fn get_module(&self, pid: u32, name: &str) -> Result<ModuleInfo> {
        let process = self
            .vmm
            .process_from_pid(pid)
            .map_err(|e| anyhow::anyhow!("Failed to get process {}: {}", pid, e))?;

        let base = process
            .get_module_base(name)
            .map_err(|e| anyhow::anyhow!("Module '{}' not found: {}", name, e))?;

        let modules = process
            .map_module(false, false)
            .map_err(|e| anyhow::anyhow!("Failed to get modules: {}", e))?;

        let size = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .map(|m| m.image_size)
            .unwrap_or(0);

        Ok(ModuleInfo { base, size })
    }

    pub fn get_kernel_drivers(&self) -> Result<Vec<KernelDriver>> {
        let drivers = self
            .vmm
            .map_kdriver()
            .map_err(|e| anyhow::anyhow!("Failed to get kernel drivers: {}", e))?;

        Ok(drivers
            .iter()
            .map(|d| KernelDriver {
                va: d.va,
                device_object: d.va_device_object,
                name: d.name.clone(),
            })
            .collect())
    }

    pub fn get_fpga_info(&self) -> Option<FpgaInfo> {
        if let Ok(lc) = self.vmm.get_leechcore() {
            let id = lc.get_option(LeechCore::LC_OPT_FPGA_FPGA_ID).unwrap_or(0);
            let major = lc
                .get_option(LeechCore::LC_OPT_FPGA_VERSION_MAJOR)
                .unwrap_or(0);
            let minor = lc
                .get_option(LeechCore::LC_OPT_FPGA_VERSION_MINOR)
                .unwrap_or(0);

            if id > 0 {
                return Some(FpgaInfo {
                    id,
                    version_major: major,
                    version_minor: minor,
                });
            }
        }
        None
    }

    pub fn read_bytes(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.read(4, addr, size)
    }

    pub fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<()> {
        self.write(4, addr, data)
    }

    pub fn read_u32_k(&self, addr: u64) -> Result<u32> {
        self.read_u32(4, addr)
    }

    pub fn read_u64_k(&self, addr: u64) -> Result<u64> {
        self.read_u64(4, addr)
    }
}
