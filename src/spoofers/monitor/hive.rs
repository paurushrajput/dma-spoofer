use anyhow::{bail, Result};
use memprocfs::Vmm;

#[derive(Debug, Clone)]
pub struct HiveInfo {
    pub va: u64,
    pub size: u32,
    pub name: String,
    pub path: String,
}

pub struct RegistryHive<'a> {
    vmm: &'a Vmm<'a>,
}

impl<'a> RegistryHive<'a> {
    pub fn new(vmm: &'a Vmm<'a>) -> Result<Self> {
        Ok(Self { vmm })
    }

    pub fn enumerate_hives(&self) -> Result<Vec<HiveInfo>> {
        let hives = self
            .vmm
            .reg_hive_list()
            .map_err(|e| anyhow::anyhow!("Failed to list hives: {}", e))?;

        let result: Vec<HiveInfo> = hives
            .iter()
            .map(|h| HiveInfo {
                va: h.va,
                size: h.size,
                name: h.name.clone(),
                path: h.path.clone(),
            })
            .collect();

        Ok(result)
    }

    pub fn find_system_hive(&self) -> Result<HiveInfo> {
        let hives = self.enumerate_hives()?;

        for hive in hives {
            let path_upper = hive.path.to_uppercase();
            let name_upper = hive.name.to_uppercase();

            if (path_upper.contains("SYSTEM") || name_upper.contains("SYSTEM"))
                && !path_upper.contains("SYSTEMALT")
            {
                return Ok(hive);
            }
        }

        bail!("SYSTEM hive not found")
    }

    pub fn read_hive(&self, hive: &HiveInfo, ra: u32, size: usize) -> Result<Vec<u8>> {
        let hives = self
            .vmm
            .reg_hive_list()
            .map_err(|e| anyhow::anyhow!("Failed to list hives: {}", e))?;

        let target = hives
            .iter()
            .find(|h| h.va == hive.va)
            .ok_or_else(|| anyhow::anyhow!("Hive not found"))?;

        target
            .reg_hive_read(ra, size, memprocfs::FLAG_NOCACHE)
            .map_err(|e| anyhow::anyhow!("Failed to read hive: {}", e))
    }

    pub fn write_hive(&self, hive: &HiveInfo, ra: u32, data: &[u8]) -> Result<()> {
        let hives = self
            .vmm
            .reg_hive_list()
            .map_err(|e| anyhow::anyhow!("Failed to list hives: {}", e))?;

        let target = hives
            .iter()
            .find(|h| h.va == hive.va)
            .ok_or_else(|| anyhow::anyhow!("Hive not found"))?;

        target
            .reg_hive_write(ra, data)
            .map_err(|e| anyhow::anyhow!("Failed to write hive: {}", e))
    }

    pub fn list_hives(&self) -> Result<()> {
        let hives = self.enumerate_hives()?;

        println!("[*] Found {} registry hive(s):", hives.len());

        for (i, hive) in hives.iter().enumerate() {
            println!("    [{}] VA: 0x{:X}", i, hive.va);
            println!("        Size: {} bytes", hive.size);
            println!("        Name: {}", hive.name);
            println!("        Path: {}", hive.path);
            println!();
        }

        Ok(())
    }
}
