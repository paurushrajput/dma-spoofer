use anyhow::{bail, Result};

use super::offsets::*;
use super::scanner::NdisScanner;
use super::types::MacAddress;
use crate::core::Dma;

const MINIPORT_CONTEXT_OSC_CTXT: u64 = 0x38;
const OSC_CTXT_PORT_MGR: u64 = 0xA60;
const PORT_MGR_MAC_ADDR_MGR: u64 = 0x30;
const MAC_ADDR_MGR_FIRST_ENTRY: u64 = 0x08;
const MAC_ADDR_ENTRY_SIZE: u64 = 0x10;
const NDIS_MINIPORT_BLOCK_SCAN_RANGE: u64 = 0x200;

pub struct IntelWifiSpoofer<'a> {
    dma: &'a Dma<'a>,
    miniport_block: u64,
    miniport_context: Option<u64>,
}

impl<'a> IntelWifiSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        println!("[*] Creating NDIS scanner...");
        let scanner = NdisScanner::new(dma)?;
        println!("[*] Enumerating adapters...");
        let adapters = scanner.enumerate_adapters()?;

        if adapters.is_empty() {
            bail!("No NDIS adapters found");
        }

        println!("[+] Found {} NDIS adapters:", adapters.len());

        for (i, adapter) in adapters.iter().enumerate() {
            println!(
                "    [{}] MAC: {} (perm: {}) @ 0x{:X}",
                i, adapter.current_mac, adapter.permanent_mac, adapter.miniport_block
            );
        }

        let intel_ouis: Vec<[u8; 3]> = vec![
            [0x00, 0x1B, 0x21],
            [0x00, 0x1C, 0xBF],
            [0x00, 0x1D, 0xE0],
            [0x00, 0x1E, 0x64],
            [0x00, 0x1E, 0x65],
            [0x00, 0x1F, 0x3B],
            [0x00, 0x1F, 0x3C],
            [0x00, 0x21, 0x5C],
            [0x00, 0x21, 0x5D],
            [0x00, 0x21, 0x6A],
            [0x00, 0x22, 0xFA],
            [0x00, 0x22, 0xFB],
            [0x00, 0x24, 0xD6],
            [0x00, 0x24, 0xD7],
            [0x3C, 0xA9, 0xF4],
            [0x48, 0x51, 0xB7],
            [0x5C, 0x51, 0x4F],
            [0x68, 0x94, 0x23],
            [0x80, 0x86, 0xF2],
            [0x8C, 0x8D, 0x28],
            [0xB4, 0x6B, 0xFC],
            [0xDC, 0x53, 0x60],
            [0xE4, 0x02, 0x9B],
            [0xF8, 0x94, 0xC2],
            [0xC8, 0x09, 0xA8],
            [0xCA, 0x09, 0xA8],
        ];

        let mut intel_adapter_block: Option<u64> = None;

        for adapter in &adapters {
            let oui = [
                adapter.permanent_mac.bytes[0],
                adapter.permanent_mac.bytes[1],
                adapter.permanent_mac.bytes[2],
            ];
            if intel_ouis.contains(&oui) {
                println!(
                    "[+] Auto-detected Intel adapter by OUI: {}",
                    adapter.permanent_mac
                );
                intel_adapter_block = Some(adapter.miniport_block);
                break;
            }
        }

        if intel_adapter_block.is_none() {
            println!(
                "\n[?] Could not auto-detect Intel WiFi. Please enter adapter index (0-{}):",
                adapters.len() - 1
            );
            print!("    Index: ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if let Ok(idx) = input.trim().parse::<usize>() {
                if idx < adapters.len() {
                    intel_adapter_block = Some(adapters[idx].miniport_block);
                }
            }
        }

        let miniport_block = match intel_adapter_block {
            Some(block) => {
                println!("[+] Using NDIS_MINIPORT_BLOCK: 0x{:X}", block);
                block
            }
            None => {
                bail!("No adapter selected");
            }
        };

        Ok(Self {
            dma,
            miniport_block,
            miniport_context: None,
        })
    }

    fn find_miniport_context(&mut self) -> Result<u64> {
        if let Some(ctx) = self.miniport_context {
            return Ok(ctx);
        }

        println!("[*] Scanning NDIS_MINIPORT_BLOCK for MiniportAdapterContext...");

        let data = self.dma.read(
            KERNEL_PID,
            self.miniport_block,
            NDIS_MINIPORT_BLOCK_SCAN_RANGE as usize,
        )?;

        println!("[*] First 16 pointers in NDIS_MINIPORT_BLOCK:");
        for i in 0..16 {
            let off = i * 8;
            if off + 8 <= data.len() {
                let ptr = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
                if ptr > 0xFFFF800000000000 {
                    println!("    [0x{:03X}] 0x{:016X} (kernel ptr)", off, ptr);
                }
            }
        }

        for offset in (0x00..NDIS_MINIPORT_BLOCK_SCAN_RANGE).step_by(8) {
            let idx = offset as usize;
            if idx + 8 > data.len() {
                break;
            }

            let ptr = u64::from_le_bytes(data[idx..idx + 8].try_into().unwrap());

            if ptr == 0 || ptr < 0xFFFF800000000000 {
                continue;
            }

            if let Ok(osc_ctxt) = self
                .dma
                .read_u64(KERNEL_PID, ptr + MINIPORT_CONTEXT_OSC_CTXT)
            {
                if osc_ctxt > 0xFFFF800000000000 {
                    if let Ok(port_mgr) =
                        self.dma.read_u64(KERNEL_PID, osc_ctxt + OSC_CTXT_PORT_MGR)
                    {
                        if port_mgr > 0xFFFF800000000000 {
                            if let Ok(mac_mgr) = self
                                .dma
                                .read_u64(KERNEL_PID, port_mgr + PORT_MGR_MAC_ADDR_MGR)
                            {
                                if mac_mgr > 0xFFFF800000000000 {
                                    if let Ok(mac_data) = self.dma.read(
                                        KERNEL_PID,
                                        mac_mgr + MAC_ADDR_MGR_FIRST_ENTRY,
                                        6,
                                    ) {
                                        let mac = MacAddress::from_bytes([
                                            mac_data[0],
                                            mac_data[1],
                                            mac_data[2],
                                            mac_data[3],
                                            mac_data[4],
                                            mac_data[5],
                                        ]);
                                        if mac.is_valid() {
                                            println!("[+] Found MiniportAdapterContext at offset 0x{:X}: 0x{:X}", offset, ptr);
                                            println!("    OSC_CTXT_GEN: 0x{:X}", osc_ctxt);
                                            println!("    CPortMgr: 0x{:X}", port_mgr);
                                            println!("    CMacAddrMgr: 0x{:X}", mac_mgr);
                                            println!("    Sample MAC: {}", mac);
                                            self.miniport_context = Some(ptr);
                                            return Ok(ptr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        println!("\n[*] Chain validation failed. Trying alternative: search for MAC in extended range...");
        let mac_bytes: [u8; 6] = [0xC8, 0x09, 0xA8, 0x94, 0x45, 0xE4];

        let extended_data = self.dma.read(KERNEL_PID, self.miniport_block, 0x2000)?;
        for i in 0..extended_data.len().saturating_sub(6) {
            if extended_data[i..i + 6] == mac_bytes {
                println!("[+] Found MAC at NDIS_MINIPORT_BLOCK + 0x{:X}", i);
            }
        }

        bail!("Could not find valid MiniportAdapterContext in NDIS_MINIPORT_BLOCK");
    }

    fn get_mac_addr_mgr(&self, miniport_ctx: u64) -> Result<u64> {
        let osc_ctxt = self
            .dma
            .read_u64(KERNEL_PID, miniport_ctx + MINIPORT_CONTEXT_OSC_CTXT)?;
        if osc_ctxt == 0 || osc_ctxt < 0xFFFF000000000000 {
            bail!("Invalid OSC_CTXT_GEN: 0x{:X}", osc_ctxt);
        }

        let port_mgr = self
            .dma
            .read_u64(KERNEL_PID, osc_ctxt + OSC_CTXT_PORT_MGR)?;
        if port_mgr == 0 || port_mgr < 0xFFFF000000000000 {
            bail!("Invalid CPortMgr: 0x{:X}", port_mgr);
        }

        let mac_addr_mgr = self
            .dma
            .read_u64(KERNEL_PID, port_mgr + PORT_MGR_MAC_ADDR_MGR)?;
        if mac_addr_mgr == 0 || mac_addr_mgr < 0xFFFF000000000000 {
            bail!("Invalid CMacAddrMgr: 0x{:X}", mac_addr_mgr);
        }

        Ok(mac_addr_mgr)
    }

    fn get_mac_at_index(&self, mac_addr_mgr: u64, index: u32) -> Result<(u64, MacAddress)> {
        if index >= 5 {
            bail!("Invalid MAC index: {}", index);
        }

        let mac_addr =
            mac_addr_mgr + MAC_ADDR_MGR_FIRST_ENTRY + (index as u64 * MAC_ADDR_ENTRY_SIZE);
        let data = self.dma.read(KERNEL_PID, mac_addr, 6)?;

        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&data[..6]);

        Ok((mac_addr, MacAddress::from_bytes(bytes)))
    }

    pub fn list(&mut self) -> Result<()> {
        println!("[*] Finding Intel WiFi MINIPORT_CONTEXT...");

        let miniport_ctx = self.find_miniport_context()?;
        println!("[+] MINIPORT_CONTEXT: 0x{:X}", miniport_ctx);

        let mac_addr_mgr = self.get_mac_addr_mgr(miniport_ctx)?;
        println!("[+] CMacAddrMgr: 0x{:X}", mac_addr_mgr);

        println!("[+] MAC Address Entries:");
        for i in 0..5 {
            match self.get_mac_at_index(mac_addr_mgr, i) {
                Ok((addr, mac)) => {
                    let valid = mac.is_valid();
                    println!(
                        "    [{}] {} @ 0x{:X} {}",
                        i,
                        mac,
                        addr,
                        if valid { "" } else { "(invalid)" }
                    );
                }
                Err(e) => {
                    println!("    [{}] Error: {}", i, e);
                }
            }
        }

        Ok(())
    }

    pub fn spoof(&mut self, new_mac: &[u8; 6]) -> Result<()> {
        println!("[*] Finding Intel WiFi MINIPORT_CONTEXT...");

        let miniport_ctx = self.find_miniport_context()?;
        println!("[+] MINIPORT_CONTEXT: 0x{:X}", miniport_ctx);

        let mac_addr_mgr = self.get_mac_addr_mgr(miniport_ctx)?;
        println!("[+] CMacAddrMgr: 0x{:X}", mac_addr_mgr);

        println!("[*] Spoofing MAC addresses...");
        println!("    New MAC: {}", MacAddress::from_bytes(*new_mac));

        for i in 0..5 {
            match self.get_mac_at_index(mac_addr_mgr, i) {
                Ok((addr, old_mac)) => {
                    if old_mac.is_valid() {
                        println!("    [{}] {} -> patching...", i, old_mac);
                        self.dma.write(KERNEL_PID, addr, new_mac)?;

                        let verify = self.dma.read(KERNEL_PID, addr, 6)?;
                        let mut verify_bytes = [0u8; 6];
                        verify_bytes.copy_from_slice(&verify[..6]);
                        println!("        Verify: {}", MacAddress::from_bytes(verify_bytes));
                    }
                }
                Err(_) => continue,
            }
        }

        println!("[+] Intel WiFi MAC spoof complete!");

        Ok(())
    }
}
