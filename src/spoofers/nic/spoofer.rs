use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use super::offsets::*;
use super::scanner::NdisScanner;
use super::types::*;
use crate::core::Dma;
use crate::hwid::{SeedConfig, SerialGenerator};

pub struct NicSpoofer<'a> {
    dma: &'a Dma<'a>,
    scanner: NdisScanner<'a>,
    adapters: Vec<NdisAdapter>,
}

impl<'a> NicSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let scanner = NdisScanner::new(dma)?;

        Ok(Self {
            dma,
            scanner,
            adapters: Vec::new(),
        })
    }

    pub fn enumerate(&mut self) -> Result<&Vec<NdisAdapter>> {
        self.adapters = self.scanner.enumerate_adapters()?;
        Ok(&self.adapters)
    }

    pub fn list(&mut self) -> Result<()> {
        println!("[*] Enumerating network adapters...");

        self.enumerate()?;

        if self.adapters.is_empty() {
            println!("[!] No network adapters found");
            return Ok(());
        }

        println!("[+] Found {} adapter(s):", self.adapters.len());

        for (i, adapter) in self.adapters.iter().enumerate() {
            println!();
            println!("    Adapter {}:", i);
            println!("        MINIPORT_BLOCK: 0x{:X}", adapter.miniport_block);
            println!("        IF_BLOCK:       0x{:X}", adapter.if_block);
            println!(
                "        Current MAC:    {} @ 0x{:X}",
                adapter.current_mac, adapter.current_mac_addr
            );
            println!(
                "        Permanent MAC:  {} @ 0x{:X}",
                adapter.permanent_mac, adapter.permanent_mac_addr
            );
        }

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        self.spoof_and_get_macs()?;
        Ok(())
    }

    pub fn spoof_and_get_macs(&mut self) -> Result<Vec<[u8; 6]>> {
        let seed_path = Path::new("hwid_seed.json");
        let config = SeedConfig::load(seed_path).unwrap_or_else(|| {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            SeedConfig::new(seed)
        });

        let mut generator = SerialGenerator::from_config(config);

        println!("[*] Enumerating network adapters...");

        self.enumerate()?;

        if self.adapters.is_empty() {
            println!("[!] No network adapters found");
            return Ok(Vec::new());
        }

        println!("[+] Found {} adapter(s)", self.adapters.len());

        let mut spoofed_macs: Vec<[u8; 6]> = Vec::new();

        for (i, adapter) in self.adapters.iter().enumerate() {
            println!();
            println!("[*] Spoofing adapter {}...", i);
            println!("    Current MAC:   {}", adapter.current_mac);
            println!("    Permanent MAC: {}", adapter.permanent_mac);

            let new_mac = self.generate_mac(&mut generator);
            println!("    New MAC:       {}", MacAddress::from_bytes(new_mac));

            self.write_mac(adapter.current_mac_addr, &new_mac)?;
            println!("    [+] Patched current MAC");

            self.write_mac(adapter.permanent_mac_addr, &new_mac)?;
            println!("    [+] Patched permanent MAC");

            let verify_current = self.read_mac(adapter.current_mac_addr)?;
            let verify_permanent = self.read_mac(adapter.permanent_mac_addr)?;
            println!("    [*] Verify current:   {}", verify_current);
            println!("    [*] Verify permanent: {}", verify_permanent);

            spoofed_macs.push(new_mac);
        }

        if let Err(e) = generator.to_config().save(seed_path) {
            println!("[!] Failed to save seed config: {}", e);
        }

        println!();
        println!("[+] NIC spoof complete!");
        println!("[*] Verify with: getmac /v");
        println!("[*] Verify with: ipconfig /all");

        Ok(spoofed_macs)
    }

    fn generate_mac(&self, generator: &mut SerialGenerator) -> [u8; 6] {
        let mac_str = generator.generate_mac();
        let mac_clean: String = mac_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        let mut mac = [0u8; 6];
        for i in 0..6 {
            if let Ok(byte) = u8::from_str_radix(&mac_clean[i * 2..i * 2 + 2], 16) {
                mac[i] = byte;
            }
        }

        mac[0] &= 0xFE;
        mac[0] |= 0x02;

        mac
    }

    fn write_mac(&self, addr: u64, mac: &[u8; 6]) -> Result<()> {
        self.dma.write(KERNEL_PID, addr, mac)
    }

    fn read_mac(&self, addr: u64) -> Result<MacAddress> {
        let data = self.dma.read(KERNEL_PID, addr, MAC_ADDRESS_LENGTH)?;
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&data[..6]);
        Ok(MacAddress::from_bytes(bytes))
    }
}
