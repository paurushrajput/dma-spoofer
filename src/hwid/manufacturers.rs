pub enum DiskManufacturer {
    WesternDigital,
    Samsung,
    Seagate,
    Crucial,
    Intel,
    Toshiba,
    Hitachi,
    Kingston,
    Micron,
    SanDisk,
    Nvme,
    Unknown,
}

impl DiskManufacturer {
    pub fn detect(model: &str) -> Self {
        let model_lower = model.to_lowercase();
        if model_lower.contains("wd") || model_lower.contains("western") {
            Self::WesternDigital
        } else if model_lower.contains("samsung") {
            Self::Samsung
        } else if model_lower.contains("seagate") || model_lower.contains("st") {
            Self::Seagate
        } else if model_lower.contains("crucial") || model_lower.contains("ct") {
            Self::Crucial
        } else if model_lower.contains("intel") {
            Self::Intel
        } else if model_lower.contains("toshiba") {
            Self::Toshiba
        } else if model_lower.contains("hitachi") || model_lower.contains("hts") {
            Self::Hitachi
        } else if model_lower.contains("kingston") || model_lower.contains("skc") {
            Self::Kingston
        } else if model_lower.contains("micron") {
            Self::Micron
        } else if model_lower.contains("sandisk") {
            Self::SanDisk
        } else if model_lower.contains("nvme") || model_lower.contains("0000_0000") {
            Self::Nvme
        } else {
            Self::Unknown
        }
    }

    pub fn serial_prefix(&self) -> &'static str {
        match self {
            Self::WesternDigital => "WD-WCC",
            Self::Samsung => "S",
            Self::Seagate => "ST",
            Self::Crucial => "CT",
            Self::Intel => "INTEL",
            Self::Toshiba => "Y",
            Self::Hitachi => "HTS",
            Self::Kingston => "SKC",
            Self::Micron => "MT",
            Self::SanDisk => "SD",
            Self::Nvme => "0000_0000_0000_0001_",
            Self::Unknown => "",
        }
    }

    pub fn serial_pattern(&self) -> &'static str {
        match self {
            Self::WesternDigital => "AAANANNNN",
            Self::Samsung => "XXXXXXXXXXXXX",
            Self::Seagate => "XXXXXXXXXXXXXX",
            Self::Crucial => "XXXXXXXXXXXXXX",
            Self::Intel => "XXXXXXXXXXX",
            Self::Toshiba => "XXXXXXXXXXXXXXX",
            Self::Hitachi => "XXXXXXXXXXXXX",
            Self::Kingston => "XXXXXXXXXXXXX",
            Self::Micron => "XXXXXXXXXXXXX",
            Self::SanDisk => "XXXXXXXXXXXXX",
            Self::Nvme => "XXXX_XXXX_XXXX_XXXX.",
            Self::Unknown => "XXXXXXXXXXXXXXXXXXXX",
        }
    }

    pub fn serial_length(&self) -> usize {
        match self {
            Self::WesternDigital => 20,
            Self::Samsung => 14,
            Self::Seagate => 16,
            Self::Crucial => 16,
            Self::Intel => 16,
            Self::Toshiba => 16,
            Self::Hitachi => 16,
            Self::Kingston => 16,
            Self::Micron => 16,
            Self::SanDisk => 16,
            Self::Nvme => 40,
            Self::Unknown => 20,
        }
    }
}

pub enum SmbiosManufacturer {
    Hp,
    Asus,
    Acer,
    Dell,
    Lenovo,
    Msi,
    Gigabyte,
    Asrock,
    Intel,
    Ami,
    Insyde,
    Unknown,
}

impl SmbiosManufacturer {
    pub fn detect(bios_vendor: &str, board_vendor: &str) -> Self {
        let combined = format!("{} {}", bios_vendor, board_vendor).to_lowercase();
        if combined.contains("hp") || combined.contains("hewlett") {
            Self::Hp
        } else if combined.contains("asus") {
            Self::Asus
        } else if combined.contains("acer") {
            Self::Acer
        } else if combined.contains("dell") {
            Self::Dell
        } else if combined.contains("lenovo") {
            Self::Lenovo
        } else if combined.contains("msi") || combined.contains("micro-star") {
            Self::Msi
        } else if combined.contains("gigabyte") {
            Self::Gigabyte
        } else if combined.contains("asrock") {
            Self::Asrock
        } else if combined.contains("intel") {
            Self::Intel
        } else if combined.contains("ami") || combined.contains("american megatrends") {
            Self::Ami
        } else if combined.contains("insyde") {
            Self::Insyde
        } else {
            Self::Unknown
        }
    }

    pub fn baseboard_pattern(&self) -> &'static str {
        match self {
            Self::Hp => "PMAAAANNAAAAAA",
            Self::Asus => "NNNNNNNNNNNNNN",
            Self::Acer => "NBAAANNNNNNNNNNNNNNNN",
            Self::Dell => "AAAAAAA",
            Self::Lenovo => "AANNNNNNN",
            Self::Msi => "AAANNNNNNNNNNN",
            Self::Gigabyte => "SNNNNNNNNNNN",
            Self::Asrock => "MNNNNNNNNNNNN",
            Self::Intel => "AAANNNNNNNNN",
            Self::Ami | Self::Insyde | Self::Unknown => "AAAAAAAAAAAAAAA",
        }
    }

    pub fn system_pattern(&self) -> &'static str {
        match self {
            Self::Hp => "NLLNNNNTCB",
            Self::Asus => "LNPDCGNNNNNNNNNN",
            Self::Acer => "NXKJZAANNNNNNNNNNNNNN",
            Self::Dell => "AAAAAAA",
            Self::Lenovo => "AANNNNNNN",
            Self::Msi
            | Self::Gigabyte
            | Self::Asrock
            | Self::Intel
            | Self::Ami
            | Self::Insyde
            | Self::Unknown => "AAAAAAAAAAAAAAA",
        }
    }

    pub fn chassis_pattern(&self) -> &'static str {
        match self {
            Self::Hp => "NLLNNNNTCB",
            Self::Asus => "LNPDCGNNNNNNNNNN",
            Self::Acer => "Chassis Serial Number",
            Self::Dell => "AAAAAAA",
            Self::Lenovo => "AANNNNNNN",
            Self::Msi
            | Self::Gigabyte
            | Self::Asrock
            | Self::Intel
            | Self::Ami
            | Self::Insyde
            | Self::Unknown => "AAAAAAAAAAAAAAA",
        }
    }
}
