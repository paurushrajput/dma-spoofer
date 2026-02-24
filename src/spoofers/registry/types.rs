#[derive(Debug, Clone)]
pub struct RegistryTrace {
    pub path: String,
    pub value_name: String,
    pub value_type: RegistryValueType,
    pub current_value: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegistryValueType {
    String,
    Dword,
    Binary,
    Qword,
}

impl RegistryTrace {
    pub fn new(
        path: String,
        value_name: String,
        value_type: RegistryValueType,
        current_value: String,
        description: String,
    ) -> Self {
        Self {
            path,
            value_name,
            value_type,
            current_value,
            description,
        }
    }

    pub fn full_path(&self) -> String {
        format!("{}\\{}", self.path, self.value_name)
    }
}

#[derive(Debug, Clone)]
pub struct NicGuid {
    pub adapter_index: String,
    pub description: String,
    pub service_name: String,
    pub net_cfg_instance_id: String,
}

impl NicGuid {
    pub fn new(
        adapter_index: String,
        description: String,
        service_name: String,
        net_cfg_instance_id: String,
    ) -> Self {
        Self {
            adapter_index,
            description,
            service_name,
            net_cfg_instance_id,
        }
    }
}
