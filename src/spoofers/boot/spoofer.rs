use anyhow::{anyhow, Result};

use crate::core::Dma;

const KUSER_SHARED_DATA: u64 = 0xFFFFF78000000000;
const SHARED_DATA_BOOT_ID: u64 = 0x2C4;
const SHARED_DATA_BOOT_TIME: u64 = 0x0;

pub struct BootSpoofer<'a> {
    dma: &'a Dma<'a>,
    ntoskrnl_base: u64,
    ntoskrnl_size: u32,
    ke_boot_time_addr: Option<u64>,
    ke_boot_time_bias_addr: Option<u64>,
    original_boot_time: Option<i64>,
    original_boot_id: Option<u32>,
}

impl<'a> BootSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module = dma.get_module(4, "ntoskrnl.exe")?;
        let ntoskrnl_base = module.base;
        let ntoskrnl_size = module.size;

        println!("[+] ntoskrnl.exe base: 0x{:X}", ntoskrnl_base);

        let mut spoofer = Self {
            dma,
            ntoskrnl_base,
            ntoskrnl_size,
            ke_boot_time_addr: None,
            ke_boot_time_bias_addr: None,
            original_boot_time: None,
            original_boot_id: None,
        };

        if let Ok(addr) = spoofer.find_ke_boot_time() {
            spoofer.ke_boot_time_addr = Some(addr);
            println!("[+] KeBootTime: 0x{:X}", addr);
        }

        Ok(spoofer)
    }

    fn find_ke_boot_time(&self) -> Result<u64> {
        let data = self
            .dma
            .read(4, self.ntoskrnl_base, self.ntoskrnl_size as usize)?;

        for i in 0..data.len().saturating_sub(20) {
            if data[i] == 0x48 && data[i + 1] == 0x8B {
                let modrm = data[i + 2];
                if modrm == 0x05 || modrm == 0x0D || modrm == 0x15 || modrm == 0x1D {
                    let rip_offset = i32::from_le_bytes(data[i + 3..i + 7].try_into().unwrap());
                    let rip = self.ntoskrnl_base + i as u64 + 7;
                    let target = (rip as i64 + rip_offset as i64) as u64;

                    if target > self.ntoskrnl_base + 0x100000
                        && target < self.ntoskrnl_base + self.ntoskrnl_size as u64
                    {
                        if let Ok(val) = self.dma.read_u64(4, target) {
                            if val > 132000000000000000 && val < 140000000000000000 {
                                return Ok(target);
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow!("Could not find KeBootTime"))
    }

    pub fn list(&self) -> Result<()> {
        println!("\n[*] Boot Identifiers");
        println!("{:-<60}", "");

        let boot_id_addr = KUSER_SHARED_DATA + SHARED_DATA_BOOT_ID;
        match self.dma.read_u32(4, boot_id_addr) {
            Ok(boot_id) => {
                println!(
                    "  SharedUserData->BootId: {} @ 0x{:X}",
                    boot_id, boot_id_addr
                );
            }
            Err(e) => {
                println!("  SharedUserData->BootId: Failed to read ({})", e);
            }
        }

        if let Some(addr) = self.ke_boot_time_addr {
            match self.dma.read_u64(4, addr) {
                Ok(boot_time) => {
                    let filetime_to_unix = (boot_time as i64 - 116444736000000000) / 10000000;
                    println!(
                        "  KeBootTime: {} (Unix: {}) @ 0x{:X}",
                        boot_time, filetime_to_unix, addr
                    );
                }
                Err(e) => {
                    println!("  KeBootTime: Failed to read ({})", e);
                }
            }
        } else {
            println!("  KeBootTime: Not found (pattern scan failed)");
        }

        let build_addr = KUSER_SHARED_DATA + 0x260;
        match self.dma.read_u32(4, build_addr) {
            Ok(build) => {
                let build_num = build & 0x0000FFFF;
                println!("  NtBuildNumber: {} @ 0x{:X}", build_num, build_addr);
            }
            Err(_) => {}
        }

        println!("{:-<60}", "");
        println!("\n[*] Note: Registry boot values (MachineGuid, BuildGUIDEx, InstallDate)");
        println!("    are handled by Option 25 (Spoof Registry Traces)");

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        println!("[*] Spoofing boot identifiers...");

        let boot_id_addr = KUSER_SHARED_DATA + SHARED_DATA_BOOT_ID;
        let current_boot_id = self.dma.read_u32(4, boot_id_addr)?;
        self.original_boot_id = Some(current_boot_id);

        let new_boot_id: u32 = (rand::random::<u32>() % 9999) + 1;

        println!(
            "[*] Patching BootId: {} -> {}",
            current_boot_id, new_boot_id
        );
        self.dma
            .write(4, boot_id_addr, &new_boot_id.to_le_bytes())?;

        let verify = self.dma.read_u32(4, boot_id_addr)?;
        if verify == new_boot_id {
            println!("[+] BootId spoofed successfully");
        } else {
            println!("[-] BootId verification failed");
        }

        if let Some(addr) = self.ke_boot_time_addr {
            let current = self.dma.read_u64(4, addr)?;
            self.original_boot_time = Some(current as i64);

            let days_offset: i64 = (rand::random::<i64>().abs() % 30 + 1) * 24 * 60 * 60 * 10000000;
            let new_time = if rand::random() {
                current.saturating_add(days_offset as u64)
            } else {
                current.saturating_sub(days_offset as u64)
            };

            println!("[*] Patching KeBootTime: {} -> {}", current, new_time);
            self.dma.write(4, addr, &new_time.to_le_bytes())?;

            let verify = self.dma.read_u64(4, addr)?;
            if verify == new_time {
                println!("[+] KeBootTime spoofed successfully");
            } else {
                println!("[-] KeBootTime verification failed");
            }
        }

        println!("\n[+] Boot identifiers spoofed!");
        println!("[*] Note: Also run Option 25 to spoof registry boot values");

        Ok(())
    }

    pub fn restore(&self) -> Result<()> {
        if let Some(boot_id) = self.original_boot_id {
            let boot_id_addr = KUSER_SHARED_DATA + SHARED_DATA_BOOT_ID;
            self.dma.write(4, boot_id_addr, &boot_id.to_le_bytes())?;
            println!("[+] Restored BootId: {}", boot_id);
        }

        if let (Some(addr), Some(time)) = (self.ke_boot_time_addr, self.original_boot_time) {
            self.dma.write(4, addr, &(time as u64).to_le_bytes())?;
            println!("[+] Restored KeBootTime: {}", time);
        }

        Ok(())
    }
}
