use anyhow::{bail, Result};

use super::hive::{HiveInfo, RegistryHive};

const CM_KEY_NODE_SIGNATURE: u16 = 0x6B6E;
const CM_KEY_VALUE_SIGNATURE: u16 = 0x6B76;

#[derive(Debug, Clone)]
pub struct KeyNode {
    pub cell_index: u32,
    pub signature: u16,
    pub flags: u16,
    pub subkey_count: u32,
    pub subkey_list: u32,
    pub value_count: u32,
    pub value_list: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct KeyValue {
    pub cell_index: u32,
    pub data_length: u32,
    pub data_offset: u32,
    pub data_type: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ValueData {
    pub value: KeyValue,
    pub data_ra: u32,
    pub data: Vec<u8>,
}

pub struct CellNavigator<'a> {
    hive_mgr: &'a RegistryHive<'a>,
}

impl<'a> CellNavigator<'a> {
    pub fn new(hive_mgr: &'a RegistryHive<'a>) -> Self {
        Self { hive_mgr }
    }

    pub fn read_key_node(&self, hive: &HiveInfo, cell_index: u32) -> Result<KeyNode> {
        let data = self.hive_mgr.read_hive(hive, cell_index, 0x50)?;

        let signature = u16::from_le_bytes(data[4..6].try_into()?);
        if signature != CM_KEY_NODE_SIGNATURE {
            bail!("Invalid key node signature: 0x{:04X}", signature);
        }

        let flags = u16::from_le_bytes(data[6..8].try_into()?);
        let subkey_count = u32::from_le_bytes(data[0x18..0x1C].try_into()?);
        let subkey_list = u32::from_le_bytes(data[0x20..0x24].try_into()?);
        let value_count = u32::from_le_bytes(data[0x28..0x2C].try_into()?);
        let value_list = u32::from_le_bytes(data[0x2C..0x30].try_into()?);
        let name_length = u16::from_le_bytes(data[0x4C..0x4E].try_into()?) as usize;

        let name = if name_length > 0 && name_length < 256 {
            let name_data = self
                .hive_mgr
                .read_hive(hive, cell_index + 0x50, name_length)?;
            if (flags & 0x20) != 0 {
                String::from_utf8_lossy(&name_data).to_string()
            } else {
                String::from_utf16_lossy(
                    &name_data
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                        .collect::<Vec<_>>(),
                )
            }
        } else {
            String::new()
        };

        Ok(KeyNode {
            cell_index,
            signature,
            flags,
            subkey_count,
            subkey_list,
            value_count,
            value_list,
            name,
        })
    }

    pub fn read_key_value(&self, hive: &HiveInfo, cell_index: u32) -> Result<KeyValue> {
        let data = self.hive_mgr.read_hive(hive, cell_index, 0x18)?;

        let signature = u16::from_le_bytes(data[4..6].try_into()?);
        if signature != CM_KEY_VALUE_SIGNATURE {
            bail!("Invalid key value signature: 0x{:04X}", signature);
        }

        let name_length = u16::from_le_bytes(data[6..8].try_into()?) as usize;
        let data_length = u32::from_le_bytes(data[8..12].try_into()?);
        let data_offset = u32::from_le_bytes(data[12..16].try_into()?);
        let data_type = u32::from_le_bytes(data[16..20].try_into()?);
        let flags = u16::from_le_bytes(data[20..22].try_into()?);

        let name = if name_length > 0 {
            let name_data = self
                .hive_mgr
                .read_hive(hive, cell_index + 0x18, name_length)?;
            if (flags & 1) != 0 {
                String::from_utf8_lossy(&name_data).to_string()
            } else {
                String::from_utf16_lossy(
                    &name_data
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                        .collect::<Vec<_>>(),
                )
            }
        } else {
            String::new()
        };

        Ok(KeyValue {
            cell_index,
            data_length,
            data_offset,
            data_type,
            name,
        })
    }

    pub fn get_root_cell(&self, hive: &HiveInfo) -> Result<u32> {
        let first_cell = self.hive_mgr.read_hive(hive, 0x20, 8)?;

        let sig = u16::from_le_bytes(first_cell[4..6].try_into()?);
        if sig == CM_KEY_NODE_SIGNATURE {
            return Ok(0x20);
        }

        for test_offset in [0x20u32, 0x24, 0x28, 0x30] {
            if let Ok(data) = self.hive_mgr.read_hive(hive, test_offset, 8) {
                let test_sig = u16::from_le_bytes(data[4..6].try_into()?);
                if test_sig == CM_KEY_NODE_SIGNATURE {
                    return Ok(test_offset);
                }
            }
        }

        Ok(0x20)
    }

    pub fn enumerate_subkeys(&self, hive: &HiveInfo, key: &KeyNode) -> Result<Vec<KeyNode>> {
        let mut subkeys = Vec::new();

        if key.subkey_count == 0 || key.subkey_list == 0xFFFFFFFF {
            return Ok(subkeys);
        }

        let list_data = self.hive_mgr.read_hive(hive, key.subkey_list, 8)?;
        let list_sig = u16::from_le_bytes(list_data[4..6].try_into()?);
        let count = u16::from_le_bytes(list_data[6..8].try_into()?);

        match list_sig {
            0x666C | 0x686C => {
                let entries_data =
                    self.hive_mgr
                        .read_hive(hive, key.subkey_list + 8, count as usize * 8)?;

                for i in 0..count as usize {
                    let offset = i * 8;
                    let cell_idx = u32::from_le_bytes(entries_data[offset..offset + 4].try_into()?);

                    if let Ok(subkey) = self.read_key_node(hive, cell_idx) {
                        subkeys.push(subkey);
                    }
                }
            }
            0x6972 | 0x696C => {
                let entries_data =
                    self.hive_mgr
                        .read_hive(hive, key.subkey_list + 8, count as usize * 4)?;

                for i in 0..count as usize {
                    let offset = i * 4;
                    let sublist_idx =
                        u32::from_le_bytes(entries_data[offset..offset + 4].try_into()?);

                    if let Ok(sub_subkeys) = self.enumerate_index_sublist(hive, sublist_idx) {
                        subkeys.extend(sub_subkeys);
                    }
                }
            }
            _ => {}
        }

        Ok(subkeys)
    }

    fn enumerate_index_sublist(&self, hive: &HiveInfo, list_index: u32) -> Result<Vec<KeyNode>> {
        let mut subkeys = Vec::new();

        let list_data = self.hive_mgr.read_hive(hive, list_index, 8)?;
        let list_sig = u16::from_le_bytes(list_data[4..6].try_into()?);
        let count = u16::from_le_bytes(list_data[6..8].try_into()?);

        if list_sig != 0x666C && list_sig != 0x686C {
            return Ok(subkeys);
        }

        let entries_data = self
            .hive_mgr
            .read_hive(hive, list_index + 8, count as usize * 8)?;

        for i in 0..count as usize {
            let offset = i * 8;
            let cell_idx = u32::from_le_bytes(entries_data[offset..offset + 4].try_into()?);

            if let Ok(subkey) = self.read_key_node(hive, cell_idx) {
                subkeys.push(subkey);
            }
        }

        Ok(subkeys)
    }

    pub fn enumerate_values(&self, hive: &HiveInfo, key: &KeyNode) -> Result<Vec<KeyValue>> {
        let mut values = Vec::new();

        if key.value_count == 0 || key.value_list == 0xFFFFFFFF {
            return Ok(values);
        }

        let list_data =
            self.hive_mgr
                .read_hive(hive, key.value_list, 4 + key.value_count as usize * 4)?;

        for i in 0..key.value_count as usize {
            let offset = 4 + i * 4;
            let cell_idx = u32::from_le_bytes(list_data[offset..offset + 4].try_into()?);

            if let Ok(value) = self.read_key_value(hive, cell_idx) {
                values.push(value);
            }
        }

        Ok(values)
    }

    pub fn find_subkey(
        &self,
        hive: &HiveInfo,
        key: &KeyNode,
        name: &str,
    ) -> Result<Option<KeyNode>> {
        let subkeys = self.enumerate_subkeys(hive, key)?;

        for subkey in subkeys {
            if subkey.name.eq_ignore_ascii_case(name) {
                return Ok(Some(subkey));
            }
        }

        Ok(None)
    }

    pub fn find_value(
        &self,
        hive: &HiveInfo,
        key: &KeyNode,
        name: &str,
    ) -> Result<Option<KeyValue>> {
        let values = self.enumerate_values(hive, key)?;

        for value in values {
            if value.name.eq_ignore_ascii_case(name) {
                return Ok(Some(value));
            }
        }

        Ok(None)
    }

    pub fn navigate_to_key(&self, hive: &HiveInfo, path: &str) -> Result<KeyNode> {
        let root_cell = self.get_root_cell(hive)?;
        let mut current = self.read_key_node(hive, root_cell)?;

        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();

        for part in parts {
            match self.find_subkey(hive, &current, part)? {
                Some(subkey) => current = subkey,
                None => bail!("Key not found: {}", part),
            }
        }

        Ok(current)
    }

    pub fn read_value_data(&self, hive: &HiveInfo, value: &KeyValue) -> Result<ValueData> {
        let actual_length = (value.data_length & 0x7FFFFFFF) as usize;
        let is_inline = (value.data_length & 0x80000000) != 0;

        let (data_ra, data) = if is_inline {
            let inline_data = value.data_offset.to_le_bytes()[..actual_length.min(4)].to_vec();
            (value.cell_index + 12, inline_data)
        } else {
            let cell_data = self
                .hive_mgr
                .read_hive(hive, value.data_offset, 4 + actual_length)?;
            (value.data_offset + 4, cell_data[4..].to_vec())
        };

        Ok(ValueData {
            value: value.clone(),
            data_ra,
            data,
        })
    }

    pub fn write_value_data(
        &self,
        hive: &HiveInfo,
        value_data: &ValueData,
        new_data: &[u8],
    ) -> Result<()> {
        let max_len = value_data.data.len();

        if new_data.len() > max_len {
            bail!(
                "New data ({} bytes) exceeds allocated size ({} bytes)",
                new_data.len(),
                max_len
            );
        }

        self.hive_mgr.write_hive(hive, value_data.data_ra, new_data)
    }
}
