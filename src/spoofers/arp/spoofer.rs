use crate::core::Dma;
use crate::spoofers::arp::offsets::*;
use crate::spoofers::arp::types::{ArpEntry, Compartment, NeighborState};
use anyhow::{anyhow, Result};

pub struct ArpSpoofer<'a> {
    dma: &'a Dma<'a>,
    tcpip_base: u64,
    tcpip_size: u32,
    ipv4_global: u64,
    entries: Vec<ArpEntry>,
}

impl<'a> ArpSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module = dma.get_module(4, "tcpip.sys")?;
        let tcpip_base = module.base;
        let tcpip_size = module.size;

        println!(
            "[+] tcpip.sys base: 0x{:X} size: 0x{:X}",
            tcpip_base, tcpip_size
        );

        let ipv4_global = Self::find_ipv4_global(dma, tcpip_base, tcpip_size)?;
        println!("[+] Ipv4Global: 0x{:X}", ipv4_global);

        Ok(Self {
            dma,
            tcpip_base,
            tcpip_size,
            ipv4_global,
            entries: Vec::new(),
        })
    }

    fn find_ipv4_global(dma: &Dma, base: u64, size: u32) -> Result<u64> {
        println!("[*] Scanning for Ipv4Global...");

        let data = dma.read(4, base, size as usize)?;

        for i in 0..data.len().saturating_sub(7) {
            if data[i] != 0x48 || data[i + 1] != 0x8D {
                continue;
            }

            let reg = data[i + 2];
            if reg != 0x05
                && reg != 0x0D
                && reg != 0x15
                && reg != 0x1D
                && reg != 0x25
                && reg != 0x2D
                && reg != 0x35
                && reg != 0x3D
            {
                continue;
            }

            let rip_offset = i32::from_le_bytes(data[i + 3..i + 7].try_into().unwrap());
            let rip = base + i as u64 + 7;
            let target = (rip as i64 + rip_offset as i64) as u64;

            if target <= base || target >= base + size as u64 {
                continue;
            }

            if let Ok(count) = dma.read_u32(4, target + GLOBAL_COMPARTMENT_COUNT) {
                if count > 0 && count < 50 {
                    if let Ok(table_ptr) = dma.read_u64(4, target + GLOBAL_COMPARTMENT_TABLE) {
                        if table_ptr > 0xFFFF800000000000 {
                            return Ok(target);
                        }
                    }
                }
            }
        }

        Err(anyhow!("Could not find Ipv4Global in tcpip.sys"))
    }

    pub fn enumerate(&mut self) -> Result<Vec<ArpEntry>> {
        self.entries.clear();

        let compartments = self.enumerate_compartments()?;
        println!("[*] Found {} compartment(s)", compartments.len());

        for compartment in &compartments {
            println!(
                "[*] Compartment {}: {} neighbors at 0x{:X}",
                compartment.id, compartment.neighbor_count, compartment.neighbor_table_addr
            );

            if compartment.neighbor_count > 0 && compartment.neighbor_count < 1000 {
                match self.enumerate_neighbors(compartment) {
                    Ok(neighbors) => {
                        self.entries.extend(neighbors);
                    }
                    Err(e) => {
                        println!("[-] Failed to enumerate neighbors: {}", e);
                    }
                }
            }
        }

        Ok(self.entries.clone())
    }

    fn enumerate_compartments(&self) -> Result<Vec<Compartment>> {
        let mut compartments = Vec::new();

        let count_addr = self.ipv4_global + GLOBAL_COMPARTMENT_COUNT;
        let table_ptr_addr = self.ipv4_global + GLOBAL_COMPARTMENT_TABLE;

        let count = self.dma.read_u32_k(count_addr)?;
        let table_ptr = self.dma.read_u64_k(table_ptr_addr)?;

        println!("[*] Compartment count: {}, table: 0x{:X}", count, table_ptr);

        if count == 0 || count > 64 || table_ptr == 0 {
            return Ok(compartments);
        }

        for i in 0..count {
            let bucket_ptr = table_ptr + (i as u64 * 16);
            let list_head = self.dma.read_u64_k(bucket_ptr)?;

            if list_head == 0 || list_head == bucket_ptr {
                continue;
            }

            let mut current = list_head;
            let mut iter_count = 0;

            while current != 0 && current != bucket_ptr && iter_count < 100 {
                let compartment_addr = current.saturating_sub(COMPARTMENT_ENTRY_OFFSET);

                if compartment_addr == 0 {
                    break;
                }

                let id = self.dma.read_u32_k(compartment_addr + COMPARTMENT_ID)?;
                let neighbor_table = compartment_addr + COMPARTMENT_NEIGHBOR_TABLE;
                let neighbor_count = self
                    .dma
                    .read_u32_k(neighbor_table + HASH_TABLE_NUM_ENTRIES)?;

                compartments.push(Compartment::new(
                    compartment_addr,
                    id,
                    neighbor_table,
                    neighbor_count,
                ));

                current = self.dma.read_u64_k(current)?;
                iter_count += 1;
            }
        }

        Ok(compartments)
    }

    fn enumerate_neighbors(&self, compartment: &Compartment) -> Result<Vec<ArpEntry>> {
        let mut neighbors = Vec::new();

        let table_size = self
            .dma
            .read_u32_k(compartment.neighbor_table_addr + HASH_TABLE_SIZE)?;
        let directory = self
            .dma
            .read_u64_k(compartment.neighbor_table_addr + HASH_TABLE_DIRECTORY)?;

        if table_size == 0 || table_size > 4096 || directory == 0 {
            return Ok(neighbors);
        }

        println!(
            "[*] Hash table: size={}, directory=0x{:X}",
            table_size, directory
        );

        for i in 0..table_size {
            let bucket_addr = directory + (i as u64 * 16);
            let list_head = self.dma.read_u64_k(bucket_addr)?;

            if list_head == 0 || list_head == bucket_addr {
                continue;
            }

            let mut current = list_head;
            let mut iter_count = 0;

            while current != 0 && current != bucket_addr && iter_count < 100 {
                let neighbor_addr = current.saturating_sub(NEIGHBOR_ENTRY_OFFSET);

                if neighbor_addr == 0 {
                    break;
                }

                match self.read_neighbor(neighbor_addr) {
                    Ok(Some(entry)) => {
                        neighbors.push(entry);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        println!(
                            "[-] Failed to read neighbor at 0x{:X}: {}",
                            neighbor_addr, e
                        );
                    }
                }

                current = self.dma.read_u64_k(current)?;
                iter_count += 1;
            }
        }

        Ok(neighbors)
    }

    fn read_neighbor(&self, addr: u64) -> Result<Option<ArpEntry>> {
        let interface_ptr = self.dma.read_u64_k(addr + NEIGHBOR_INTERFACE)?;
        let state_raw = self.dma.read_u32_k(addr + NEIGHBOR_STATE)?;
        let refcount = self.dma.read_u64_k(addr + NEIGHBOR_REFCOUNT)?;

        if interface_ptr == 0 || refcount == 0 {
            return Ok(None);
        }

        let state = NeighborState::from_raw(state_raw);

        if matches!(
            state,
            NeighborState::Unreachable | NeighborState::Incomplete
        ) {
            return Ok(None);
        }

        let mac_addr_location = addr + NEIGHBOR_DL_ADDRESS;
        let mac_bytes = self.dma.read_bytes(mac_addr_location, DL_ADDRESS_SIZE)?;

        let mut mac_address = [0u8; 6];
        mac_address.copy_from_slice(&mac_bytes);

        if mac_address == [0u8; 6] || mac_address == [0xFF; 6] {
            return Ok(None);
        }

        Ok(Some(ArpEntry::new(
            addr,
            interface_ptr,
            state,
            mac_address,
            mac_addr_location,
        )))
    }

    pub fn list(&self) -> &[ArpEntry] {
        &self.entries
    }

    pub fn print_entries(&self) {
        println!("\n[*] ARP Cache ({} entries):", self.entries.len());
        println!("{:-<70}", "");
        println!(
            "{:<18} {:<14} {:<16}",
            "MAC Address", "State", "Neighbor Addr"
        );
        println!("{:-<70}", "");

        for entry in &self.entries {
            println!(
                "{:<18} {:<14} 0x{:X}",
                entry.mac_string(),
                entry.state.as_str(),
                entry.neighbor_addr
            );
        }
        println!("{:-<70}", "");
    }

    pub fn spoof_mac(&self, old_mac: &[u8; 6], new_mac: &[u8; 6]) -> Result<u32> {
        let mut spoofed = 0;

        for entry in &self.entries {
            if &entry.mac_address == old_mac {
                println!(
                    "[*] Spoofing {} -> {} at 0x{:X}",
                    entry.mac_string(),
                    format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]
                    ),
                    entry.mac_addr_location
                );

                self.dma.write_bytes(entry.mac_addr_location, new_mac)?;
                spoofed += 1;
            }
        }

        Ok(spoofed)
    }

    pub fn spoof_all(&self) -> Result<u32> {
        let mut spoofed = 0;

        for entry in &self.entries {
            let mut new_mac = [0u8; 6];
            new_mac[0] = (entry.mac_address[0] & 0xFC) | 0x02;
            for i in 1..6 {
                new_mac[i] = rand::random();
            }

            println!(
                "[*] Spoofing {} -> {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                entry.mac_string(),
                new_mac[0],
                new_mac[1],
                new_mac[2],
                new_mac[3],
                new_mac[4],
                new_mac[5]
            );

            self.dma.write_bytes(entry.mac_addr_location, &new_mac)?;
            spoofed += 1;
        }

        Ok(spoofed)
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.enumerate()?;
        Ok(())
    }
}
