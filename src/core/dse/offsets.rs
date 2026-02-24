pub const KERNEL_PID: u32 = 4;

pub const DSE_DISABLED: u32 = 0x00000000;
pub const DSE_ENABLED: u32 = 0x00000006;
pub const DSE_TEST_MODE: u32 = 0x00000008;

pub const CI_DLL_NAME: &str = "CI.dll";
pub const CI_INITIALIZE_EXPORT: &str = "CiInitialize";

pub const WIN10_1507_BUILD: u32 = 10240;
pub const WIN10_1709_BUILD: u32 = 16299;
pub const WIN11_22H2_BUILD: u32 = 22621;
pub const WIN11_24H2_BUILD: u32 = 26100;

pub const JMP_REL32_OPCODE: u8 = 0xE9;
pub const CALL_REL32_OPCODE: u8 = 0xE8;
pub const MOV_CS_ECX_OPCODE: [u8; 2] = [0x89, 0x0D];
pub const MOV_CS_EAX_OPCODE: [u8; 2] = [0x89, 0x05];

pub const MOV_R9_RBX: [u8; 3] = [0x4C, 0x8B, 0xCB];
pub const MOV_R8_RDI: [u8; 3] = [0x4C, 0x8B, 0xC7];
pub const MOV_R8D_EDI: [u8; 3] = [0x44, 0x8B, 0xC7];
pub const MOV_RDX_RSI: [u8; 3] = [0x48, 0x8B, 0xD6];
pub const MOV_ECX_EBP: [u8; 2] = [0x8B, 0xCD];

pub const CI_INITIALIZE_SEARCH_SIZE: usize = 0x6E;
pub const CIP_INITIALIZE_SEARCH_SIZE: usize = 0x4A;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
