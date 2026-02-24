use std::collections::HashSet;

use anyhow::{bail, Result};

use super::offsets::*;
use super::types::*;
use crate::core::Dma;

pub struct NdisScanner<'a> {
    dma: &'a Dma<'a>,
    ndis_base: u64,
    ndis_size: u32,
}

impl<'a> NdisScanner<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Result<Self> {
        let module_info = dma.get_module(KERNEL_PID, "ndis.sys")?;

        Ok(Self {
            dma,
            ndis_base: module_info.base,
            ndis_size: module_info.size,
        })
    }

    pub fn find_minidriver_list(&self) -> Result<u64> {
        let pattern: [u8; 11] = [
            0x48, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0xF0,
        ];
        let mask = "xxx????xxxx";

        let data = self
            .dma
            .read(KERNEL_PID, self.ndis_base, self.ndis_size as usize)?;

        for i in 0..data.len().saturating_sub(pattern.len()) {
            let mut matched = true;
            for (j, &p) in pattern.iter().enumerate() {
                if mask.as_bytes()[j] == b'x' && data[i + j] != p {
                    matched = false;
                    break;
                }
            }

            if matched {
                let rip = self.ndis_base + i as u64 + 7;
                let offset = i32::from_le_bytes(data[i + 3..i + 7].try_into().unwrap());
                let list_addr = (rip as i64 + offset as i64) as u64;
                return Ok(list_addr);
            }
        }

        bail!("ndisMiniDriverList pattern not found")
    }

    pub fn enumerate_adapters(&self) -> Result<Vec<NdisAdapter>> {
        let mut adapters = Vec::new();
        let mut seen_miniports: HashSet<u64> = HashSet::new();

        let list_addr = self.find_minidriver_list()?;
        let first_driver = self.dma.read_u64(KERNEL_PID, list_addr)?;

        if first_driver == 0 {
            bail!("ndisMiniDriverList is empty")
        }

        let mut current_driver = first_driver;
        let mut driver_count = 0;

        while current_driver != 0 && driver_count < 100 {
            driver_count += 1;

            let miniport_queue = self.dma.read_u64(
                KERNEL_PID,
                current_driver + NDIS_DRIVER_BLOCK_MINIPORT_QUEUE,
            )?;

            let mut current_miniport = miniport_queue;
            let mut miniport_count = 0;

            while current_miniport != 0 && miniport_count < 100 {
                if seen_miniports.contains(&current_miniport) {
                    break;
                }
                seen_miniports.insert(current_miniport);
                miniport_count += 1;

                if let Ok(adapter) = self.read_adapter_info(current_miniport) {
                    if adapter.current_mac.is_valid() {
                        adapters.push(adapter);
                    }
                }

                current_miniport = self.dma.read_u64(
                    KERNEL_PID,
                    current_miniport + NDIS_MINIPORT_BLOCK_NEXT_MINIPORT,
                )?;
            }

            current_driver = self
                .dma
                .read_u64(KERNEL_PID, current_driver + NDIS_DRIVER_BLOCK_NEXT_DRIVER)?;
        }

        Ok(adapters)
    }

    fn read_adapter_info(&self, miniport_block: u64) -> Result<NdisAdapter> {
        let if_block = self
            .dma
            .read_u64(KERNEL_PID, miniport_block + NDIS_MINIPORT_BLOCK_IF_BLOCK)?;

        if if_block == 0 {
            bail!("IF_BLOCK is null")
        }

        let current_mac_addr = if_block + IF_BLOCK_IF_PHYS_ADDRESS + IF_PHYSICAL_ADDRESS_ADDRESS;
        let permanent_mac_addr =
            if_block + IF_BLOCK_PERMANENT_PHYS_ADDRESS + IF_PHYSICAL_ADDRESS_ADDRESS;

        let current_mac = self.read_mac_address(current_mac_addr)?;
        let permanent_mac = self.read_mac_address(permanent_mac_addr)?;

        Ok(NdisAdapter::new(
            miniport_block,
            if_block,
            current_mac_addr,
            permanent_mac_addr,
            current_mac,
            permanent_mac,
        ))
    }

    fn read_mac_address(&self, addr: u64) -> Result<MacAddress> {
        let data = self.dma.read(KERNEL_PID, addr, MAC_ADDRESS_LENGTH)?;
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&data[..6]);
        Ok(MacAddress::from_bytes(bytes))
    }
}
