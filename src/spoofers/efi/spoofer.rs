use anyhow::{anyhow, Result};

use super::shellcode::{
    generate_inline_hook_shellcode, generate_jump_to_hook, generate_random_platform_data,
    string_to_utf16le, INLINE_HOOK_PATTERN,
};
use crate::core::Dma;
use crate::utils::codecave::find_best_codecave;

pub struct EfiSpoofer<'a> {
    dma: &'a Dma<'a>,
    ntoskrnl_base: u64,
    ntoskrnl_size: u32,
    hal_efi_table_ptr: u64,
    hal_get_env_var_addr: u64,
    inline_hook_addr: u64,
    original_bytes: [u8; 14],
    hook_addr: Option<u64>,
    spoofed_data_addr: Option<u64>,
    var_name_addr: Option<u64>,
}

impl<'a> EfiSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module = dma.get_module(4, "ntoskrnl.exe")?;
        let ntoskrnl_base = module.base;
        let ntoskrnl_size = module.size;

        println!(
            "[+] ntoskrnl.exe base: 0x{:X} size: 0x{:X}",
            ntoskrnl_base, ntoskrnl_size
        );

        let hal_efi_table_ptr = Self::find_hal_efi_table(dma, ntoskrnl_base, ntoskrnl_size)?;
        println!(
            "[+] HalEfiRuntimeServicesTable ptr: 0x{:X}",
            hal_efi_table_ptr
        );

        let table_addr = dma.read_u64(4, hal_efi_table_ptr)?;
        if table_addr == 0 {
            return Err(anyhow!(
                "HalEfiRuntimeServicesTable is NULL - not an EFI system?"
            ));
        }
        println!("[+] HalEfiRuntimeServicesTable: 0x{:X}", table_addr);

        let hal_get_env_var_addr =
            Self::find_hal_get_environment_variable_ex(dma, ntoskrnl_base, ntoskrnl_size)?;
        println!(
            "[+] HalGetEnvironmentVariableEx: 0x{:X}",
            hal_get_env_var_addr
        );

        let inline_hook_addr = Self::find_inline_hook_location(dma, hal_get_env_var_addr)?;
        println!("[+] Inline hook location: 0x{:X}", inline_hook_addr);

        Ok(Self {
            dma,
            ntoskrnl_base,
            ntoskrnl_size,
            hal_efi_table_ptr,
            hal_get_env_var_addr,
            inline_hook_addr,
            original_bytes: [0u8; 14],
            hook_addr: None,
            spoofed_data_addr: None,
            var_name_addr: None,
        })
    }

    fn find_hal_efi_table(dma: &Dma, base: u64, size: u32) -> Result<u64> {
        println!("[*] Scanning for HalEfiRuntimeServicesTable...");

        let data = dma.read(4, base, size as usize)?;

        for i in 0..data.len().saturating_sub(15) {
            if data[i] == 0x48 && data[i + 1] == 0x8B && data[i + 2] == 0x05 {
                let has_test = (i + 7..std::cmp::min(i + 20, data.len().saturating_sub(3)))
                    .any(|j| data[j] == 0x48 && data[j + 1] == 0x85 && data[j + 2] == 0xC0);

                if has_test {
                    let rip_offset = i32::from_le_bytes(data[i + 3..i + 7].try_into().unwrap());
                    let rip = base + i as u64 + 7;
                    let target = (rip as i64 + rip_offset as i64) as u64;

                    if let Ok(ptr) = dma.read_u64(4, target) {
                        if ptr > 0xFFFFF80000000000 && ptr < 0xFFFFFFFFFFFFFFFF {
                            if let Ok(func) = dma.read_u64(4, ptr + 24) {
                                if func > 0xFFFFF80000000000 {
                                    return Ok(target);
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow!("Could not find HalEfiRuntimeServicesTable"))
    }

    fn find_hal_get_environment_variable_ex(dma: &Dma, base: u64, size: u32) -> Result<u64> {
        println!("[*] Scanning for HalGetEnvironmentVariableEx...");

        let data = dma.read(4, base, size as usize)?;

        let pattern: [u8; 16] = [
            0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
            0x83, 0xEC,
        ];

        for i in 0..data.len().saturating_sub(0x200) {
            if data[i..i + pattern.len()] == pattern {
                let func_addr = base + i as u64;

                for j in i..std::cmp::min(i + 0x180, data.len().saturating_sub(9)) {
                    if data[j..j + 4] == [0x48, 0x8B, 0x40, 0x18]
                        && data[j + 4..j + 6] == [0xFF, 0xD0]
                    {
                        return Ok(func_addr);
                    }
                }
            }
        }

        Err(anyhow!("Could not find HalGetEnvironmentVariableEx"))
    }

    fn find_inline_hook_location(dma: &Dma, func_addr: u64) -> Result<u64> {
        let data = dma.read(4, func_addr, 0x200)?;

        for i in 0..data.len().saturating_sub(9) {
            if data[i..i + 4] == [0x48, 0x8B, 0x40, 0x18] && data[i + 4..i + 6] == [0xFF, 0xD0] {
                return Ok(func_addr + i as u64);
            }
        }

        Err(anyhow!(
            "Could not find inline hook pattern in HalGetEnvironmentVariableEx"
        ))
    }

    pub fn list(&self) -> Result<()> {
        let table_addr = self.dma.read_u64(4, self.hal_efi_table_ptr)?;

        println!("\n[*] EFI Runtime Services Table @ 0x{:X}", table_addr);
        println!("{:-<60}", "");

        let get_time = self.dma.read_u64(4, table_addr + 16)?;
        let get_var = self.dma.read_u64(4, table_addr + 24)?;
        let get_next = self.dma.read_u64(4, table_addr + 32)?;
        let set_var = self.dma.read_u64(4, table_addr + 40)?;

        println!("  [2] GetTime:              0x{:X}", get_time);
        println!("  [3] GetVariable:          0x{:X}", get_var);
        println!("  [4] GetNextVariableName:  0x{:X}", get_next);
        println!("  [5] SetVariable:          0x{:X}", set_var);
        println!("{:-<60}", "");

        println!("\n[*] Inline Hook Info:");
        println!(
            "  HalGetEnvironmentVariableEx: 0x{:X}",
            self.hal_get_env_var_addr
        );
        println!(
            "  Hook location:               0x{:X}",
            self.inline_hook_addr
        );

        if self.hook_addr.is_some() {
            println!("[!] Hook is currently ACTIVE");
        }

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        let vmm = self.dma.vmm();

        println!("[*] Finding codecave for hook...");
        let codecave = find_best_codecave(vmm, 512)?;

        println!(
            "[+] Using codecave at 0x{:X} ({} bytes)",
            codecave.address, codecave.size
        );

        let spoofed_data = generate_random_platform_data();
        let spoofed_data_len = spoofed_data.len() as u32;

        let var_name = string_to_utf16le("PlatformData");
        let var_name_len = (var_name.len() / 2) as u16;

        let spoofed_data_addr = codecave.address;
        let var_name_addr = codecave.address + 0x80;
        let hook_code_addr = codecave.address + 0x100;

        self.dma.write(4, spoofed_data_addr, &spoofed_data)?;
        println!("[+] Spoofed data written to 0x{:X}", spoofed_data_addr);

        self.dma.write(4, var_name_addr, &var_name)?;
        println!("[+] Variable name written to 0x{:X}", var_name_addr);

        let original_bytes_vec = self.dma.read(4, self.inline_hook_addr, 14)?;
        self.original_bytes.copy_from_slice(&original_bytes_vec);
        println!(
            "[+] Saved original bytes: {:02X?}",
            &self.original_bytes[..9]
        );

        let return_addr = self.inline_hook_addr + 9;

        let hook_code = generate_inline_hook_shellcode(
            &self.original_bytes[..9].try_into().unwrap(),
            return_addr,
            self.hal_efi_table_ptr,
            spoofed_data_addr,
            spoofed_data_len,
            var_name_addr,
            var_name_len,
        );

        self.dma.write(4, hook_code_addr, &hook_code)?;
        println!(
            "[+] Hook shellcode ({} bytes) written to 0x{:X}",
            hook_code.len(),
            hook_code_addr
        );

        let jump_stub = generate_jump_to_hook(hook_code_addr);

        println!(
            "[*] Installing inline hook at 0x{:X}...",
            self.inline_hook_addr
        );
        self.dma.write(4, self.inline_hook_addr, &jump_stub)?;

        let verify = self.dma.read(4, self.inline_hook_addr, 14)?;
        if verify != jump_stub {
            return Err(anyhow!("Failed to install inline hook"));
        }

        self.hook_addr = Some(hook_code_addr);
        self.spoofed_data_addr = Some(spoofed_data_addr);
        self.var_name_addr = Some(var_name_addr);

        println!("[+] Inline hook installed!");
        println!("[+] PlatformData will return spoofed data");
        println!("[+] CFG bypass: YES (no indirect call modification)");

        Ok(())
    }

    pub fn remove_hook(&mut self) -> Result<()> {
        if self.hook_addr.is_none() {
            println!("[*] No hook installed");
            return Ok(());
        }

        println!(
            "[*] Restoring original bytes at 0x{:X}...",
            self.inline_hook_addr
        );
        self.dma
            .write(4, self.inline_hook_addr, &self.original_bytes)?;

        let restored = self.dma.read(4, self.inline_hook_addr, 14)?;
        if restored != self.original_bytes {
            return Err(anyhow!("Failed to restore original bytes"));
        }

        self.hook_addr = None;
        self.spoofed_data_addr = None;
        self.var_name_addr = None;

        println!("[+] Hook removed, original code restored");

        Ok(())
    }

    pub fn is_efi_available(&self) -> bool {
        self.dma
            .read_u64(4, self.hal_efi_table_ptr)
            .map(|ptr| ptr != 0)
            .unwrap_or(false)
    }
}
