use std::fmt;

#[derive(Debug, Clone)]
pub struct MacAddress {
    pub bytes: [u8; 6],
}

impl MacAddress {
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    pub fn is_valid(&self) -> bool {
        let all_zeros = self.bytes.iter().all(|&b| b == 0);
        let all_ones = self.bytes.iter().all(|&b| b == 0xFF);
        !all_zeros && !all_ones
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        )
    }
}

#[derive(Debug, Clone)]
pub struct NdisAdapter {
    pub miniport_block: u64,
    pub if_block: u64,
    pub current_mac_addr: u64,
    pub permanent_mac_addr: u64,
    pub current_mac: MacAddress,
    pub permanent_mac: MacAddress,
}

impl NdisAdapter {
    pub fn new(
        miniport_block: u64,
        if_block: u64,
        current_mac_addr: u64,
        permanent_mac_addr: u64,
        current_mac: MacAddress,
        permanent_mac: MacAddress,
    ) -> Self {
        Self {
            miniport_block,
            if_block,
            current_mac_addr,
            permanent_mac_addr,
            current_mac,
            permanent_mac,
        }
    }
}
