use anyhow::{anyhow, Result};

use crate::core::Dma;
use crate::utils::codecave::{CodecaveFinder, CodecaveInfo, CodecaveStrategy};

use super::offsets::*;

pub struct TpmDispatchHook<'a> {
    dma: &'a Dma<'a>,
    tpm_base: u64,
    dispatch_table_addr: u64,
    original_handler: u64,
    original_bytes: Option<Vec<u8>>,
    codecave: Option<CodecaveInfo>,
    hooked: bool,
}

impl<'a> TpmDispatchHook<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Self {
        Self {
            dma,
            tpm_base: 0,
            dispatch_table_addr: 0,
            original_handler: 0,
            original_bytes: None,
            codecave: None,
            hooked: false,
        }
    }

    pub fn find_tpm_driver(&mut self) -> Result<()> {
        println!("[*] Locating TPM driver...");

        let drivers = self.dma.get_kernel_drivers()?;

        let tpm_driver = drivers
            .iter()
            .find(|d| {
                let name = d.name.to_lowercase();
                name == "tpm"
                    || name == "tpm.sys"
                    || name.ends_with("\\tpm.sys")
                    || name.ends_with("\\tpm")
            })
            .ok_or_else(|| anyhow!("TPM driver not found"))?;

        println!(
            "    TPM driver object: 0x{:X} ({})",
            tpm_driver.va, tpm_driver.name
        );

        let module = self
            .dma
            .get_module(KERNEL_PID, "tpm.sys")
            .or_else(|_| self.dma.get_module(KERNEL_PID, "tpm"))?;
        self.tpm_base = module.base;
        println!("    tpm.sys base: 0x{:X}", module.base);

        self.dispatch_table_addr =
            tpm_driver.va + DRIVER_OBJECT_MAJOR_FUNCTION + (IRP_MJ_DEVICE_CONTROL as u64 * 8);
        self.original_handler = self.dma.read_u64(KERNEL_PID, self.dispatch_table_addr)?;

        println!("    IRP_MJ_DEVICE_CONTROL: 0x{:X}", self.original_handler);

        Ok(())
    }

    pub fn find_rwx_codecave(&mut self) -> Result<()> {
        println!("[*] Searching for RWX codecave...");

        self.scan_rwx_sections()?;

        let finder =
            CodecaveFinder::new(self.dma.vmm(), CodecaveStrategy::RwxOnly, MIN_CODECAVE_SIZE);

        if let Ok(cave) = finder.find_best() {
            println!(
                "    Found RWX codecave in {} at 0x{:X} ({} bytes)",
                cave.module_name, cave.address, cave.size
            );
            self.codecave = Some(cave);
            return Ok(());
        }

        println!("    Standard search failed, scanning inside RWX sections...");
        match self.find_rwx_in_init_sections() {
            Ok(cave) => {
                println!(
                    "    Found RWX codecave in {} ({}) at 0x{:X} ({} bytes)",
                    cave.module_name, cave.section_name, cave.address, cave.size
                );
                self.codecave = Some(cave);
                Ok(())
            }
            Err(e) => {
                println!("    No RWX codecave found: {}", e);
                Err(anyhow!("No RWX codecave available - cannot safely hook"))
            }
        }
    }

    fn scan_rwx_sections(&self) -> Result<()> {
        let process = self.dma.vmm().process_from_pid(KERNEL_PID)?;
        let modules = process.map_module(false, false)?;

        println!("    Scanning {} modules for RWX sections...", modules.len());

        let mut rwx_count = 0;
        for module in modules.iter() {
            if let Ok(sections) = process.map_module_section(&module.name) {
                for section in sections.iter() {
                    let is_r = (section.characteristics & 0x40000000) != 0;
                    let is_w = (section.characteristics & 0x80000000) != 0;
                    let is_x = (section.characteristics & 0x20000000) != 0;

                    if is_r && is_w && is_x {
                        rwx_count += 1;

                        let section_addr = module.va_base + section.virtual_address as u64;
                        let zeros = if let Ok(data) = process
                            .mem_read(section_addr, 64.min(section.misc_virtual_size as usize))
                        {
                            data.iter().filter(|&&b| b == 0).count()
                        } else {
                            0
                        };

                        println!(
                            "    [RWX] {} - {} (VA: 0x{:X}, Size: 0x{:X}, zeros in first 64: {})",
                            module.name,
                            section.name,
                            section.virtual_address,
                            section.misc_virtual_size,
                            zeros
                        );
                    }
                }
            }
        }

        if rwx_count == 0 {
            println!("    No RWX sections found in any module");
        } else {
            println!("    Found {} RWX sections", rwx_count);
        }

        Ok(())
    }

    fn find_rwx_in_init_sections(&self) -> Result<CodecaveInfo> {
        let process = self.dma.vmm().process_from_pid(KERNEL_PID)?;
        let modules = process.map_module(false, false)?;

        let skip_sections = ["INIT", "INITDATA", ".INIT", "PAGE", "PAGEDATA"];

        for module in modules.iter() {
            if let Ok(sections) = process.map_module_section(&module.name) {
                for section in sections.iter() {
                    if skip_sections
                        .iter()
                        .any(|s| section.name.eq_ignore_ascii_case(s))
                    {
                        continue;
                    }

                    let is_r = (section.characteristics & 0x40000000) != 0;
                    let is_w = (section.characteristics & 0x80000000) != 0;
                    let is_x = (section.characteristics & 0x20000000) != 0;

                    if is_r && is_w && is_x && section.misc_virtual_size >= MIN_CODECAVE_SIZE as u32
                    {
                        let section_addr = module.va_base + section.virtual_address as u64;

                        if process.mem_virt2phys(section_addr).is_err() {
                            println!(
                                "    Skipping {} - {} (not mapped)",
                                module.name, section.name
                            );
                            continue;
                        }

                        if let Ok(data) =
                            process.mem_read(section_addr, section.misc_virtual_size as usize)
                        {
                            let mut best_start = 0;
                            let mut best_len = 0;
                            let mut current_start = 0;
                            let mut current_len = 0;

                            for (i, &b) in data.iter().enumerate() {
                                if b == 0 {
                                    if current_len == 0 {
                                        current_start = i;
                                    }
                                    current_len += 1;
                                } else {
                                    if current_len > best_len {
                                        best_start = current_start;
                                        best_len = current_len;
                                    }
                                    current_len = 0;
                                }
                            }
                            if current_len > best_len {
                                best_start = current_start;
                                best_len = current_len;
                            }

                            if best_len >= MIN_CODECAVE_SIZE {
                                let cave_addr = section_addr + best_start as u64;
                                let aligned_addr = (cave_addr + 0xF) & !0xF;
                                let aligned_len = best_len - ((aligned_addr - cave_addr) as usize);

                                if process.mem_virt2phys(aligned_addr).is_err() {
                                    continue;
                                }

                                if aligned_len >= MIN_CODECAVE_SIZE {
                                    return Ok(CodecaveInfo {
                                        address: aligned_addr,
                                        size: aligned_len,
                                        module_name: module.name.clone(),
                                        section_name: section.name.clone(),
                                        is_rwx: true,
                                        quality_score: 100,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow!(
            "No mapped RWX codecave found (INIT sections are unmapped after boot)"
        ))
    }

    pub fn install(&mut self) -> Result<()> {
        if self.original_handler == 0 {
            return Err(anyhow!("TPM driver not found - call find_tpm_driver first"));
        }

        let codecave = self
            .codecave
            .as_ref()
            .ok_or_else(|| anyhow!("No codecave found - call find_rwx_codecave first"))?;

        if !codecave.is_rwx {
            return Err(anyhow!("Codecave is not RWX - would cause BSOD"));
        }

        println!("[*] Installing dispatch hook...");

        let original = self
            .dma
            .read(KERNEL_PID, self.original_handler, DETOUR_SIZE)?;
        println!("    Original bytes: {:02X?}", original);
        self.original_bytes = Some(original.clone());

        let shellcode = self.generate_hook_shellcode(&original)?;
        println!("    Shellcode size: {} bytes", shellcode.len());

        println!(
            "    Verifying codecave 0x{:X} is accessible...",
            codecave.address
        );
        let test_read = self.dma.read(KERNEL_PID, codecave.address, 16)?;
        println!("    Current bytes at codecave: {:02X?}", test_read);

        println!("    Writing to codecave 0x{:X}...", codecave.address);

        let vmm = self.dma.vmm();
        let process = vmm.process_from_pid(KERNEL_PID)?;

        match process.mem_virt2phys(codecave.address) {
            Ok(phys_addr) => {
                println!("    Physical address: 0x{:X}", phys_addr);
                vmm.mem_write(phys_addr, &shellcode)
                    .map_err(|e| anyhow!("Physical write failed: {}", e))?;
            }
            Err(_) => {
                println!("    VA->PA failed, trying virtual write...");
                process
                    .mem_write(codecave.address, &shellcode)
                    .map_err(|e| anyhow!("Virtual write failed: {}", e))?;
            }
        }

        let verify = self.dma.read(KERNEL_PID, codecave.address, 16)?;
        if verify[0..4] == shellcode[0..4] {
            println!("    Write verified successfully");
        } else {
            println!("    WARNING: Write verification failed!");
            println!("    Expected: {:02X?}", &shellcode[0..16]);
            println!("    Got:      {:02X?}", verify);
        }

        let detour = generate_detour(codecave.address);
        println!("    Installing detour at 0x{:X}...", self.original_handler);

        match process.mem_virt2phys(self.original_handler) {
            Ok(handler_phys) => {
                println!("    Handler physical address: 0x{:X}", handler_phys);
                vmm.mem_write(handler_phys, &detour)
                    .map_err(|e| anyhow!("Failed to write detour: {}", e))?;
            }
            Err(_) => {
                println!("    Handler VA->PA failed, trying virtual write...");
                process
                    .mem_write(self.original_handler, &detour)
                    .map_err(|e| anyhow!("Failed to write detour: {}", e))?;
            }
        }

        self.hooked = true;
        println!("[+] Hook installed successfully");

        Ok(())
    }

    fn generate_hook_shellcode(&self, original_bytes: &[u8]) -> Result<Vec<u8>> {
        let return_addr = self.original_handler + DETOUR_SIZE as u64;

        let mut code = Vec::with_capacity(MIN_CODECAVE_SIZE);

        code.extend_from_slice(original_bytes);

        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&return_addr.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xE0]);

        while code.len() < MIN_CODECAVE_SIZE {
            code.push(0xCC);
        }

        Ok(code)
    }

    pub fn remove(&mut self) -> Result<()> {
        if !self.hooked {
            return Err(anyhow!("Hook not installed"));
        }

        let original = self
            .original_bytes
            .as_ref()
            .ok_or_else(|| anyhow!("No original bytes saved"))?;

        println!("[*] Removing hook...");

        let vmm = self.dma.vmm();
        let process = vmm.process_from_pid(KERNEL_PID)?;
        let handler_phys = process
            .mem_virt2phys(self.original_handler)
            .map_err(|e| anyhow!("Failed to translate handler VA to PA: {}", e))?;

        vmm.mem_write(handler_phys, original)
            .map_err(|e| anyhow!("Failed to restore original bytes: {}", e))?;

        self.hooked = false;
        println!("[+] Hook removed");

        Ok(())
    }

    pub fn is_hooked(&self) -> bool {
        self.hooked
    }
}

impl<'a> Drop for TpmDispatchHook<'a> {
    fn drop(&mut self) {
        if self.hooked {
            let _ = self.remove();
        }
    }
}

fn generate_detour(target: u64) -> Vec<u8> {
    let mut detour = Vec::with_capacity(DETOUR_SIZE);
    detour.extend_from_slice(&[0x48, 0xB8]);
    detour.extend_from_slice(&target.to_le_bytes());
    detour.extend_from_slice(&[0xFF, 0xE0]);
    detour
}
