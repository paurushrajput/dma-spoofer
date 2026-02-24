use std::collections::HashMap;

pub struct CharacterSets {
    sets: HashMap<&'static str, &'static str>,
}

impl CharacterSets {
    pub fn new() -> Self {
        let mut sets = HashMap::new();
        sets.insert("hex_upper", "0123456789ABCDEF");
        sets.insert("hex_lower", "0123456789abcdef");
        sets.insert("alphanumeric_upper", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        sets.insert(
            "alphanumeric_mixed",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        );
        sets.insert("numeric", "0123456789");
        sets.insert("letters_upper", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        sets.insert("letters_lower", "abcdefghijklmnopqrstuvwxyz");
        Self { sets }
    }

    pub fn get(&self, name: &str) -> Option<&'static str> {
        self.sets.get(name).copied()
    }
}

impl Default for CharacterSets {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PatternDefinitions {
    patterns: HashMap<&'static str, &'static str>,
}

impl PatternDefinitions {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert("bios_serial", "LLLLNNNNNNNN");
        patterns.insert("baseboard_serial", "AAAAAAAAAAAAAAA");
        patterns.insert("chassis_serial", "LLNNLLNNNNNNNNNNNNNN");
        patterns.insert("system_serial", "LLNNLLNNNNNNNNNNNNNN");
        patterns.insert("disk_serial_generic", "XXXXXXXXXXXXXXXXXXXX");
        patterns.insert(
            "disk_serial_nvme",
            "0000_0000_0000_0001_XXXX_XXXX_XXXX_XXXX.",
        );
        patterns.insert("mac_address", "XX:XX:XX:XX:XX:XX");
        patterns.insert("mac_address_dash", "XX-XX-XX-XX-XX-XX");
        patterns.insert("uuid", "XXXXXXXX-XXXX-4XXX-YXXX-XXXXXXXXXXXX");
        patterns.insert("guid", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX");
        patterns.insert("volume_id", "XXXX-XXXX");
        patterns.insert("volume_guid", "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}");
        patterns.insert("processor_id", "XXXXXXXXXXXXXXXX");
        patterns.insert("memory_serial", "XXXXXXXX");
        patterns.insert("tpm_ek", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        patterns.insert("windows_product_id", "NNNNN-NNN-NNNNNNN-NNNNN");
        Self { patterns }
    }

    pub fn get(&self, name: &str) -> Option<&'static str> {
        self.patterns.get(name).copied()
    }

    pub fn list(&self) -> Vec<&'static str> {
        self.patterns.keys().copied().collect()
    }
}

impl Default for PatternDefinitions {
    fn default() -> Self {
        Self::new()
    }
}
