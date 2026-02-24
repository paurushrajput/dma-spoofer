#[derive(Debug, Clone)]
pub struct EfiVariable {
    pub name: String,
    pub guid: [u8; 16],
    pub attributes: u32,
    pub data: Vec<u8>,
    pub spoof_data: Option<Vec<u8>>,
}

impl EfiVariable {
    pub fn new(name: &str, guid: [u8; 16], attributes: u32) -> Self {
        Self {
            name: name.to_string(),
            guid,
            attributes,
            data: Vec::new(),
            spoof_data: None,
        }
    }

    pub fn with_spoof_data(mut self, data: Vec<u8>) -> Self {
        self.spoof_data = Some(data);
        self
    }

    pub fn guid_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes(self.guid[0..4].try_into().unwrap()),
            u16::from_le_bytes(self.guid[4..6].try_into().unwrap()),
            u16::from_le_bytes(self.guid[6..8].try_into().unwrap()),
            self.guid[8],
            self.guid[9],
            self.guid[10],
            self.guid[11],
            self.guid[12],
            self.guid[13],
            self.guid[14],
            self.guid[15]
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EfiRuntimeServicesTable {
    pub address: u64,
    pub get_time: u64,
    pub get_variable: u64,
    pub get_next_variable_name: u64,
    pub set_variable: u64,
}

impl EfiRuntimeServicesTable {
    pub fn new(address: u64) -> Self {
        Self {
            address,
            get_time: 0,
            get_variable: 0,
            get_next_variable_name: 0,
            set_variable: 0,
        }
    }
}

pub const TRACKED_VARIABLES: &[&str] = &[
    "PlatformData",
    "PlatformLangCodes",
    "PlatformLang",
    "ConOut",
    "ConIn",
    "ErrOut",
    "BootOrder",
    "Boot0000",
    "Boot0001",
    "SetupMode",
    "SecureBoot",
];

pub fn should_spoof_variable(name: &str) -> bool {
    TRACKED_VARIABLES
        .iter()
        .any(|&v| v.eq_ignore_ascii_case(name))
}
