pub const MACHINE_GUID_PATH: &str = "HKLM\\SOFTWARE\\Microsoft\\Cryptography";
pub const MACHINE_GUID_VALUE: &str = "MachineGuid";

pub const WINDOWS_NT_PATH: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
pub const PRODUCT_ID_VALUE: &str = "ProductId";
pub const BUILD_GUID_VALUE: &str = "BuildGUIDEx";
pub const INSTALL_DATE_VALUE: &str = "InstallDate";
pub const INSTALL_TIME_VALUE: &str = "InstallTime";
pub const DIGITAL_PRODUCT_ID_VALUE: &str = "DigitalProductId";
pub const DIGITAL_PRODUCT_ID4_VALUE: &str = "DigitalProductId4";

pub const SQM_CLIENT_PATH: &str = "HKLM\\SOFTWARE\\Microsoft\\SQMClient";
pub const SQM_MACHINE_ID_VALUE: &str = "MachineId";

pub const NETWORK_CARDS_PATH: &str =
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";
pub const SERVICE_NAME_VALUE: &str = "ServiceName";

pub const MOUNTED_DEVICES_PATH: &str = "HKLM\\SYSTEM\\MountedDevices";

pub const CONTROL_SET_PATHS: [&str; 2] = [
    "HKLM\\SYSTEM\\ControlSet001",
    "HKLM\\SYSTEM\\CurrentControlSet",
];

pub const NIC_CLASS_GUID: &str = "{4d36e972-e325-11ce-bfc1-08002be10318}";
pub const DISK_CLASS_GUID: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";
