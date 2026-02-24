use std::fs;
use std::path::Path;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use super::manufacturers::{DiskManufacturer, SmbiosManufacturer};
use super::oui::OuiDatabase;
use super::patterns::{CharacterSets, PatternDefinitions};

#[derive(Serialize, Deserialize, Clone)]
pub struct GeneratedSerials {
    pub disk_serial: Option<String>,
    pub mac_addresses: Vec<String>,
    pub smbios_system: Option<String>,
    pub smbios_baseboard: Option<String>,
    pub smbios_chassis: Option<String>,
    pub gpu_uuid: Option<String>,
    pub volume_guids: Vec<String>,
    pub tpm_ek: Option<String>,
}

impl Default for GeneratedSerials {
    fn default() -> Self {
        Self {
            disk_serial: None,
            mac_addresses: Vec::new(),
            smbios_system: None,
            smbios_baseboard: None,
            smbios_chassis: None,
            gpu_uuid: None,
            volume_guids: Vec::new(),
            tpm_ek: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SeedConfig {
    pub seed: u64,
    pub generated: GeneratedSerials,
}

impl SeedConfig {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            generated: GeneratedSerials::default(),
        }
    }

    pub fn load(path: &Path) -> Option<Self> {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
    }
}

pub struct SerialGenerator {
    rng: ChaCha20Rng,
    seed: u64,
    charsets: CharacterSets,
    patterns: PatternDefinitions,
    oui_db: OuiDatabase,
    generated: GeneratedSerials,
}

impl SerialGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            seed,
            charsets: CharacterSets::new(),
            patterns: PatternDefinitions::new(),
            oui_db: OuiDatabase::new(),
            generated: GeneratedSerials::default(),
        }
    }

    pub fn from_config(config: SeedConfig) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(config.seed),
            seed: config.seed,
            charsets: CharacterSets::new(),
            patterns: PatternDefinitions::new(),
            oui_db: OuiDatabase::new(),
            generated: config.generated,
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn reseed(&mut self, new_seed: u64) {
        self.seed = new_seed;
        self.rng = ChaCha20Rng::seed_from_u64(new_seed);
        self.generated = GeneratedSerials::default();
    }

    pub fn generated(&self) -> &GeneratedSerials {
        &self.generated
    }

    pub fn to_config(&self) -> SeedConfig {
        SeedConfig {
            seed: self.seed,
            generated: self.generated.clone(),
        }
    }

    pub fn generate_from_pattern(&mut self, pattern: &str) -> String {
        pattern
            .chars()
            .map(|c| match c {
                'X' => self.random_char("hex_upper"),
                'x' => self.random_char("hex_lower"),
                'N' => self.random_char("numeric"),
                'L' => self.random_char("letters_upper"),
                'l' => self.random_char("letters_lower"),
                'A' => self.random_char("alphanumeric_upper"),
                'Y' => self.random_char("alphanumeric_mixed"),
                _ => c,
            })
            .collect()
    }

    pub fn generate_named_pattern(&mut self, name: &str) -> Option<String> {
        self.patterns
            .get(name)
            .map(|p| self.generate_from_pattern(p))
    }

    pub fn generate_hex(&mut self, length: usize) -> String {
        (0..length).map(|_| self.random_char("hex_upper")).collect()
    }

    pub fn generate_alphanumeric(&mut self, length: usize) -> String {
        (0..length)
            .map(|_| self.random_char("alphanumeric_upper"))
            .collect()
    }

    pub fn generate_numeric(&mut self, length: usize) -> String {
        (0..length).map(|_| self.random_char("numeric")).collect()
    }

    pub fn generate_uuid(&mut self) -> String {
        let mut uuid = self.generate_from_pattern("XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX");
        let mut chars: Vec<char> = uuid.chars().collect();
        if chars.len() >= 20 {
            let variants = ['8', '9', 'A', 'B'];
            chars[19] = variants[self.rng.gen_range(0..4)];
        }
        uuid = chars.into_iter().collect();
        self.generated.gpu_uuid = Some(format!("GPU-{}", uuid.to_lowercase()));
        uuid
    }

    pub fn generate_guid(&mut self) -> String {
        let guid = self.generate_from_pattern("{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}");
        self.generated.volume_guids.push(guid.clone());
        guid
    }

    pub fn generate_mac(&mut self) -> String {
        let first_hex = self.random_char("hex_upper");
        let valid_second = ['2', '6', 'A', 'E'];
        let second_hex = valid_second[self.rng.gen_range(0..4)];
        let remaining = self.generate_from_pattern("XX-XX-XX-XX-XX");
        let mac = format!("{}{}-{}", first_hex, second_hex, remaining);
        self.generated.mac_addresses.push(mac.clone());
        mac
    }

    pub fn generate_mac_with_oui(&mut self, manufacturer: &str) -> String {
        let mac = if let Some(oui) = self.oui_db.get_oui(manufacturer) {
            let suffix = self.generate_from_pattern("XX:XX:XX");
            format!("{}:{}", oui, suffix)
        } else {
            self.generate_mac().replace('-', ":")
        };
        if !self.generated.mac_addresses.contains(&mac) {
            self.generated.mac_addresses.push(mac.clone());
        }
        mac
    }

    pub fn generate_mac_for_adapter(&mut self, name: &str, description: &str) -> String {
        if let Some(oui) = self.oui_db.detect_manufacturer(name, description) {
            let suffix = self.generate_from_pattern("XX:XX:XX");
            let mac = format!("{}:{}", oui, suffix);
            self.generated.mac_addresses.push(mac.clone());
            mac
        } else {
            self.generate_mac().replace('-', ":")
        }
    }

    pub fn generate_disk_serial(&mut self, model: &str) -> String {
        let manufacturer = DiskManufacturer::detect(model);
        let prefix = manufacturer.serial_prefix();
        let pattern = manufacturer.serial_pattern();
        let suffix = self.generate_from_pattern(pattern);
        let serial = format!("{}{}", prefix, suffix);
        self.generated.disk_serial = Some(serial.clone());
        serial
    }

    pub fn generate_disk_serial_bytes(&mut self, model: &str, target_len: usize) -> Vec<u8> {
        let serial = self.generate_disk_serial(model);
        let mut bytes = serial.into_bytes();
        bytes.resize(target_len, b' ');
        bytes
    }

    pub fn generate_smbios_serial(
        &mut self,
        bios_vendor: &str,
        board_vendor: &str,
        table_type: u8,
    ) -> String {
        let manufacturer = SmbiosManufacturer::detect(bios_vendor, board_vendor);
        let pattern = match table_type {
            1 => manufacturer.system_pattern(),
            2 => manufacturer.baseboard_pattern(),
            3 => manufacturer.chassis_pattern(),
            _ => "AAAAAAAAAAAAAAA",
        };
        let serial = self.generate_from_pattern(pattern);
        match table_type {
            1 => self.generated.smbios_system = Some(serial.clone()),
            2 => self.generated.smbios_baseboard = Some(serial.clone()),
            3 => self.generated.smbios_chassis = Some(serial.clone()),
            _ => {}
        }
        serial
    }

    pub fn generate_smbios_string(&mut self, length: usize) -> String {
        self.generate_alphanumeric(length)
    }

    pub fn generate_tpm_ek(&mut self) -> String {
        let ek = self.generate_hex(40);
        self.generated.tpm_ek = Some(ek.clone());
        ek
    }

    pub fn generate_volume_id(&mut self) -> String {
        self.generate_from_pattern("XXXX-XXXX")
    }

    pub fn generate_processor_id(&mut self) -> String {
        self.generate_from_pattern("XXXXXXXXXXXXXXXX")
    }

    pub fn generate_memory_serial(&mut self) -> String {
        self.generate_from_pattern("XXXXXXXX")
    }

    pub fn generate_random_bytes(&mut self, size: usize) -> Vec<u8> {
        (0..size).map(|_| self.rng.gen()).collect()
    }

    fn random_char(&mut self, charset_name: &str) -> char {
        if let Some(charset) = self.charsets.get(charset_name) {
            let chars: Vec<char> = charset.chars().collect();
            if !chars.is_empty() {
                return chars[self.rng.gen_range(0..chars.len())];
            }
        }
        '?'
    }
}
