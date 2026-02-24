pub const TYPE_BIOS: u8 = 0;
pub const TYPE_SYSTEM: u8 = 1;
pub const TYPE_BASEBOARD: u8 = 2;
pub const TYPE_CHASSIS: u8 = 3;
pub const TYPE_PROCESSOR: u8 = 4;
pub const TYPE_MEMORY: u8 = 17;
pub const TYPE_END: u8 = 127;

#[derive(Debug, Clone)]
pub struct SmbiosHeader {
    pub table_type: u8,
    pub length: u8,
    pub handle: u16,
}

impl SmbiosHeader {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        Some(Self {
            table_type: data[0],
            length: data[1],
            handle: u16::from_le_bytes([data[2], data[3]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SmbiosTable {
    pub header: SmbiosHeader,
    pub offset: u64,
    pub strings: Vec<String>,
}

impl SmbiosTable {
    pub fn type_name(&self) -> &str {
        match self.header.table_type {
            TYPE_BIOS => "BIOS Information",
            TYPE_SYSTEM => "System Information",
            TYPE_BASEBOARD => "Baseboard Information",
            TYPE_CHASSIS => "Chassis Information",
            TYPE_PROCESSOR => "Processor Information",
            TYPE_MEMORY => "Memory Device",
            TYPE_END => "End of Table",
            _ => "Unknown",
        }
    }
}
