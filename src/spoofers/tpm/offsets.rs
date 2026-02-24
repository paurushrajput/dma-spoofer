pub const KERNEL_PID: u32 = 4;

pub const TPM_CC_READ_PUBLIC: u32 = 0x00000173;
pub const TPM_CC_CREATE_PRIMARY: u32 = 0x00000131;

pub const TPM_RSP_TAG_OFFSET: usize = 0;
pub const TPM_RSP_SIZE_OFFSET: usize = 2;
pub const TPM_RSP_RC_OFFSET: usize = 6;
pub const TPM_RSP_HEADER_SIZE: usize = 10;

pub const TPM2B_PUBLIC_SIZE_OFFSET: usize = 0;
pub const TPMT_PUBLIC_TYPE_OFFSET: usize = 2;
pub const TPMT_PUBLIC_NAME_ALG_OFFSET: usize = 4;

pub const RSA_UNIQUE_SIZE_OFFSET: usize = 0x1C;
pub const RSA_UNIQUE_BUFFER_OFFSET: usize = 0x1E;

pub const TPM_WMI_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI";
pub const TPM_ENDORSEMENT_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement";

pub const EK_PUB_VALUE: &str = "EKpub";
pub const EK_CERT_VALUE: &str = "EKCert";
pub const EK_PUB_HASH_VALUE: &str = "EKpubHash";

pub const DRIVER_OBJECT_MAJOR_FUNCTION: u64 = 0x70;
pub const IRP_MJ_DEVICE_CONTROL: u32 = 14;
pub const MAJOR_FUNCTION_ENTRY_SIZE: u64 = 8;

pub const DISPATCH_COMMAND_VTABLE_OFFSET: u64 = 0x80;

pub const MIN_CODECAVE_SIZE: usize = 512;
pub const DETOUR_SIZE: usize = 12;
