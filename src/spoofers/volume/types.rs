#[derive(Debug, Clone)]
pub struct VolumeGuid {
    pub entry_addr: u64,
    pub name_buffer_addr: u64,
    pub guid: String,
    pub full_path: String,
    pub is_active: bool,
}

impl VolumeGuid {
    pub fn new(
        entry_addr: u64,
        name_buffer_addr: u64,
        guid: String,
        full_path: String,
        is_active: bool,
    ) -> Self {
        Self {
            entry_addr,
            name_buffer_addr,
            guid,
            full_path,
            is_active,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountedDevice {
    pub entry_addr: u64,
    pub device_name: String,
    pub unique_id: Vec<u8>,
    pub volume_guids: Vec<VolumeGuid>,
}

impl MountedDevice {
    pub fn new(entry_addr: u64, device_name: String, unique_id: Vec<u8>) -> Self {
        Self {
            entry_addr,
            device_name,
            unique_id,
            volume_guids: Vec::new(),
        }
    }

    pub fn add_volume_guid(&mut self, guid: VolumeGuid) {
        self.volume_guids.push(guid);
    }
}
