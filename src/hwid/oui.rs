use std::collections::HashMap;

pub struct OuiDatabase {
    entries: HashMap<&'static str, &'static str>,
}

impl OuiDatabase {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert("intel", "E4:C7:67");
        entries.insert("realtek", "00:E0:4C");
        entries.insert("asus", "00:26:18");
        entries.insert("acer", "18:06:FF");
        entries.insert("dell", "D0:43:1E");
        entries.insert("hp", "64:4E:D7");
        entries.insert("lenovo", "48:C3:5A");
        entries.insert("samsung", "64:1B:2F");
        entries.insert("apple", "60:FD:A6");
        entries.insert("microsoft", "70:F8:AE");
        entries.insert("sony", "F4:64:12");
        entries.insert("ibm", "40:F2:E9");
        entries.insert("nvidia", "48:B0:2D");
        entries.insert("amd", "74:27:2C");
        entries.insert("google", "60:70:6C");
        entries.insert("amazon", "84:28:59");
        entries.insert("cisco", "E8:0A:B9");
        entries.insert("oracle", "00:21:F6");
        entries.insert("huawei", "E0:06:30");
        entries.insert("lg", "AC:5A:F0");
        entries.insert("htc", "40:4E:36");
        entries.insert("nokia", "28:6F:B9");
        entries.insert("oneplus", "AC:C0:48");
        entries.insert("oppo", "E4:40:97");
        entries.insert("honor", "0C:B9:83");
        entries.insert("realme", "5C:A0:6C");
        entries.insert("blackberry", "48:9D:24");
        entries.insert("alcatel", "88:3C:93");
        entries.insert("zte", "F0:1B:24");
        entries.insert("infinix", "E8:C2:DD");
        entries.insert("tecno", "4C:A3:A7");
        entries.insert("qualcomm", "00:03:7F");
        entries.insert("broadcom", "00:10:18");
        entries.insert("marvell", "00:50:43");
        entries.insert("mediatek", "00:0C:E7");
        entries.insert("killer", "9C:EB:E8");
        entries.insert("ralink", "00:0C:43");
        entries.insert("atheros", "00:03:7F");
        Self { entries }
    }

    pub fn get_oui(&self, manufacturer: &str) -> Option<&'static str> {
        self.entries
            .get(manufacturer.to_lowercase().as_str())
            .copied()
    }

    pub fn detect_manufacturer(
        &self,
        adapter_name: &str,
        adapter_description: &str,
    ) -> Option<&'static str> {
        let combined = format!("{} {}", adapter_name, adapter_description).to_lowercase();
        for (manufacturer, oui) in &self.entries {
            if combined.contains(manufacturer) {
                return Some(oui);
            }
        }
        None
    }

    pub fn get_oui_bytes(&self, manufacturer: &str) -> Option<[u8; 3]> {
        self.get_oui(manufacturer).and_then(|oui| {
            let parts: Vec<&str> = oui.split(':').collect();
            if parts.len() != 3 {
                return None;
            }
            let mut bytes = [0u8; 3];
            for (i, part) in parts.iter().enumerate() {
                bytes[i] = u8::from_str_radix(part, 16).ok()?;
            }
            Some(bytes)
        })
    }

    pub fn list_manufacturers(&self) -> Vec<&'static str> {
        self.entries.keys().copied().collect()
    }
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::new()
    }
}
