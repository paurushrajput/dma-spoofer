pub const DRIVER_CONTEXT_GLOBAL: u64 = 0x132DF30;
pub const DEVICE_MGR_BASE: u64 = 0x1F0;
pub const DEV_MGR_DEVICE_COUNT: u64 = 0x3F440;
pub const DEVICE_CTX_GPU_MGR: u64 = 0x1F70;
pub const GPU_MGR_GPU_COUNT: u64 = 0x1A20;
pub const GPU_MGR_GPU_ARRAY: u64 = 0x19E0;

pub const GPU_UUID_SIZE: usize = 16;
pub const GPU_UUID_SEARCH_SIZE: usize = 0x2000;

pub const KNOWN_UUID_OFFSETS: &[u64] = &[
    0x4D9, 0x4DA, 0x848, 0x849, 0xBB5, 0xBBC, 0xBCC, 0xBCD, 0xC34, 0xC35,
];

pub const GPU_UUID_INITIALIZED_581: u64 = 0x4D9;
pub const GPU_UUID_DATA_581: u64 = 0x4DA;
