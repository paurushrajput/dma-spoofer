use std::fmt;

#[derive(Debug, Clone)]
pub struct GpuUuid {
    pub initialized: bool,
    pub data: [u8; 16],
}

impl GpuUuid {
    pub fn new_uninit() -> Self {
        Self {
            initialized: false,
            data: [0u8; 16],
        }
    }

    pub fn from_bytes(data: [u8; 16]) -> Self {
        Self {
            initialized: true,
            data,
        }
    }

    pub fn format(&self) -> String {
        if !self.initialized {
            return "Not initialized".to_string();
        }

        format!(
            "GPU-{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data[0], self.data[1], self.data[2], self.data[3],
            self.data[4], self.data[5],
            self.data[6], self.data[7],
            self.data[8], self.data[9],
            self.data[10], self.data[11], self.data[12], self.data[13], self.data[14], self.data[15]
        )
    }
}

impl fmt::Display for GpuUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}
