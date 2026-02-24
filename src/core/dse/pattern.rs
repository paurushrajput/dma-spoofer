use anyhow::{anyhow, Result};

use super::offsets::*;

pub struct PatternScanner<'a> {
    data: &'a [u8],
    base: u64,
}

impl<'a> PatternScanner<'a> {
    pub fn new(data: &'a [u8], base: u64) -> Self {
        Self { data, base }
    }

    pub fn find_cip_initialize_pre_1709(&self, ci_init_offset: usize) -> Result<u64> {
        let search_end = (ci_init_offset + 0x48).min(self.data.len());
        let mut i = ci_init_offset;

        while i < search_end {
            let len = self.get_instruction_length(i)?;

            if len == 5 && self.data[i] == JMP_REL32_OPCODE {
                let rel_offset = i32::from_le_bytes([
                    self.data[i + 1],
                    self.data[i + 2],
                    self.data[i + 3],
                    self.data[i + 4],
                ]);

                let cip_init_va = (self.base as i64)
                    .wrapping_add(i as i64)
                    .wrapping_add(5)
                    .wrapping_add(rel_offset as i64) as u64;

                return Ok(cip_init_va);
            }

            i += len;
        }

        Err(anyhow!("CipInitialize JMP not found in CiInitialize"))
    }

    pub fn find_cip_initialize_post_1709(&self, ci_init_offset: usize) -> Result<u64> {
        let search_end = (ci_init_offset + CI_INITIALIZE_SEARCH_SIZE).min(self.data.len());
        let mut i = ci_init_offset;
        let mut stage = 0u32;

        while i < search_end {
            let len = self.get_instruction_length(i)?;

            match stage {
                0 => {
                    if len == 3 && self.matches_bytes(i, &MOV_R9_RBX) {
                        stage = 1;
                    }
                }
                1 => {
                    if len == 3 && self.matches_bytes(i, &MOV_R8_RDI) {
                        stage = 2;
                    } else {
                        stage = 0;
                    }
                }
                2 => {
                    if len == 3 && self.matches_bytes(i, &MOV_RDX_RSI) {
                        stage = 3;
                    } else {
                        stage = 0;
                    }
                }
                3 => {
                    if len == 2 && self.matches_bytes(i, &MOV_ECX_EBP) {
                        stage = 4;
                    } else {
                        stage = 0;
                    }
                }
                4 => {
                    if len == 5 && self.data[i] == CALL_REL32_OPCODE {
                        let rel_offset = i32::from_le_bytes([
                            self.data[i + 1],
                            self.data[i + 2],
                            self.data[i + 3],
                            self.data[i + 4],
                        ]);

                        let cip_init_va = (self.base as i64)
                            .wrapping_add(i as i64)
                            .wrapping_add(5)
                            .wrapping_add(rel_offset as i64)
                            as u64;

                        return Ok(cip_init_va);
                    }
                    stage = 0;
                }
                _ => stage = 0,
            }

            i += len;
        }

        Err(anyhow!(
            "CipInitialize CALL not found in CiInitialize (post-1709 pattern)"
        ))
    }

    pub fn find_cip_initialize_24h2(&self, ci_init_offset: usize) -> Result<u64> {
        let search_end = (ci_init_offset + CI_INITIALIZE_SEARCH_SIZE).min(self.data.len());
        let mut i = ci_init_offset;
        let mut stage = 0u32;
        let mut skip_count = 0u32;

        while i < search_end {
            let len = self.get_instruction_length(i)?;

            match stage {
                0 => {
                    if len == 3 && self.matches_bytes(i, &MOV_R9_RBX) {
                        stage = 1;
                        skip_count = 0;
                    }
                }
                1 => {
                    if len == 3 && self.matches_bytes(i, &MOV_R8D_EDI) {
                        stage = 2;
                        skip_count = 0;
                    } else {
                        stage = 0;
                    }
                }
                2 => {
                    if len == 3 && self.matches_bytes(i, &MOV_RDX_RSI) {
                        stage = 3;
                    } else {
                        skip_count += 1;
                        if skip_count > 2 {
                            stage = 0;
                        }
                    }
                }
                3 => {
                    if len == 2 && self.matches_bytes(i, &MOV_ECX_EBP) {
                        stage = 4;
                    } else {
                        stage = 0;
                    }
                }
                4 => {
                    if len == 5 && self.data[i] == CALL_REL32_OPCODE {
                        let rel_offset = i32::from_le_bytes([
                            self.data[i + 1],
                            self.data[i + 2],
                            self.data[i + 3],
                            self.data[i + 4],
                        ]);

                        let cip_init_va = (self.base as i64)
                            .wrapping_add(i as i64)
                            .wrapping_add(5)
                            .wrapping_add(rel_offset as i64)
                            as u64;

                        return Ok(cip_init_va);
                    }
                    stage = 0;
                }
                _ => stage = 0,
            }

            i += len;
        }

        Err(anyhow!(
            "CipInitialize CALL not found in CiInitialize (24H2 pattern)"
        ))
    }

    pub fn find_g_ci_options(&self, cip_init_offset: usize) -> Result<u64> {
        let search_end = (cip_init_offset + CIP_INITIALIZE_SEARCH_SIZE).min(self.data.len());
        let mut i = cip_init_offset;

        while i < search_end {
            let len = self.get_instruction_length(i)?;

            if len == 6 {
                if self.matches_bytes(i, &MOV_CS_ECX_OPCODE)
                    || self.matches_bytes(i, &MOV_CS_EAX_OPCODE)
                {
                    let rel_offset = i32::from_le_bytes([
                        self.data[i + 2],
                        self.data[i + 3],
                        self.data[i + 4],
                        self.data[i + 5],
                    ]);

                    let g_ci_options_va = (self.base as i64)
                        .wrapping_add(i as i64)
                        .wrapping_add(6)
                        .wrapping_add(rel_offset as i64)
                        as u64;

                    return Ok(g_ci_options_va);
                }
            }

            i += len;
        }

        Err(anyhow!(
            "g_CiOptions MOV instruction not found in CipInitialize"
        ))
    }

    fn matches_bytes(&self, offset: usize, pattern: &[u8]) -> bool {
        if offset + pattern.len() > self.data.len() {
            return false;
        }
        &self.data[offset..offset + pattern.len()] == pattern
    }

    fn get_instruction_length(&self, offset: usize) -> Result<usize> {
        if offset >= self.data.len() {
            return Err(anyhow!("Offset out of bounds"));
        }

        let opcode = self.data[offset];

        match opcode {
            0x48 | 0x4C | 0x49 | 0x4D => {
                if offset + 2 < self.data.len() {
                    let next = self.data[offset + 1];
                    let modrm = self.data[offset + 2];
                    match next {
                        0x89 | 0x8B | 0x03 | 0x2B | 0x33 | 0x3B | 0x8D | 0xC7 | 0x85 | 0x87 => {
                            return Ok(self.calc_modrm_length(modrm, 2));
                        }
                        0x63 => return Ok(3),
                        0xB8..=0xBF => return Ok(10),
                        0xC1 => return Ok(4),
                        _ => {}
                    }
                }
                Ok(3)
            }
            0x44 | 0x45 | 0x41 => {
                if offset + 1 < self.data.len() {
                    let next = self.data[offset + 1];
                    match next {
                        0x89 | 0x8B | 0x8A => return Ok(3),
                        0x0F => return Ok(4),
                        _ => {}
                    }
                }
                Ok(2)
            }
            0x89 | 0x8B => {
                if offset + 1 < self.data.len() {
                    let modrm = self.data[offset + 1];
                    return Ok(self.calc_modrm_length(modrm, 1));
                }
                Ok(2)
            }
            0x8A | 0x88 => Ok(2),
            0xE8 | 0xE9 => Ok(5),
            0xEB => Ok(2),
            0x0F => {
                if offset + 1 < self.data.len() {
                    match self.data[offset + 1] {
                        0x84 | 0x85 | 0x8C..=0x8F => return Ok(6),
                        0xB6 | 0xB7 | 0xBE | 0xBF => return Ok(3),
                        _ => {}
                    }
                }
                Ok(2)
            }
            0x50..=0x5F => Ok(1),
            0xC3 | 0xCC | 0xC9 => Ok(1),
            0x90 => Ok(1),
            0xB8..=0xBF => Ok(5),
            0xB0..=0xB7 => Ok(2),
            0x33 | 0x2B | 0x03 | 0x23 | 0x0B | 0x13 | 0x1B | 0x3B => Ok(2),
            0x83 => Ok(3),
            0x81 => {
                if offset + 1 < self.data.len() {
                    let modrm = self.data[offset + 1];
                    return Ok(self.calc_modrm_length(modrm, 1) + 4);
                }
                Ok(6)
            }
            0xFF => {
                if offset + 1 < self.data.len() {
                    let modrm = self.data[offset + 1];
                    return Ok(self.calc_modrm_length(modrm, 1));
                }
                Ok(2)
            }
            0x66 => {
                if offset + 1 < self.data.len() {
                    return Ok(1 + self.get_instruction_length(offset + 1)?);
                }
                Ok(1)
            }
            _ => Ok(1),
        }
    }

    fn calc_modrm_length(&self, modrm: u8, prefix_len: usize) -> usize {
        let mod_bits = (modrm >> 6) & 0x03;
        let rm = modrm & 0x07;

        let mut len = prefix_len + 1;

        if rm == 4 && mod_bits != 3 {
            len += 1;
        }

        match mod_bits {
            0 => {
                if rm == 5 {
                    len += 4;
                }
            }
            1 => len += 1,
            2 => len += 4,
            _ => {}
        }

        len
    }
}
