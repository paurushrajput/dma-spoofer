use crate::hwid::SerialGenerator;

pub fn generate_inline_hook_shellcode(
    original_bytes: &[u8; 9],
    return_addr: u64,
    hal_efi_table_addr: u64,
    spoofed_data_addr: u64,
    spoofed_data_len: u32,
    target_var_name_addr: u64,
    target_var_name_len: u16,
) -> Vec<u8> {
    let mut code = Vec::new();

    code.extend_from_slice(&[0x50]);
    code.extend_from_slice(&[0x51]);
    code.extend_from_slice(&[0x52]);
    code.extend_from_slice(&[0x41, 0x50]);
    code.extend_from_slice(&[0x41, 0x51]);
    code.extend_from_slice(&[0x41, 0x52]);
    code.extend_from_slice(&[0x41, 0x53]);
    code.extend_from_slice(&[0x56]);
    code.extend_from_slice(&[0x57]);

    code.extend_from_slice(&[0x48, 0x89, 0xCE]);

    code.extend_from_slice(&[0x48, 0xBF]);
    code.extend_from_slice(&target_var_name_addr.to_le_bytes());

    code.extend_from_slice(&[0x66, 0xB9]);
    code.extend_from_slice(&target_var_name_len.to_le_bytes());

    code.extend_from_slice(&[0xF3, 0x66, 0xA7]);

    code.extend_from_slice(&[0x75]);
    let jne_offset_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0x4C, 0x8B, 0x4C, 0x24, 0x20]);

    code.extend_from_slice(&[0x4D, 0x85, 0xC9]);
    code.extend_from_slice(&[0x74]);
    let jz_datasize_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&spoofed_data_len.to_le_bytes());

    code.extend_from_slice(&[0x49, 0x39, 0x01]);

    code.extend_from_slice(&[0x72]);
    let jb_buffer_small_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0x49, 0x89, 0x01]);

    code.extend_from_slice(&[0x48, 0x8B, 0x7C, 0x24, 0x70]);

    code.extend_from_slice(&[0x48, 0x85, 0xFF]);
    code.extend_from_slice(&[0x74]);
    let jz_data_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0x48, 0xBE]);
    code.extend_from_slice(&spoofed_data_addr.to_le_bytes());

    code.extend_from_slice(&[0xB9]);
    code.extend_from_slice(&spoofed_data_len.to_le_bytes());

    code.extend_from_slice(&[0xF3, 0xA4]);

    code[jz_data_pos] = (code.len() - jz_data_pos - 1) as u8;
    code[jz_datasize_pos] = (code.len() - jz_datasize_pos - 1) as u8;

    code.extend_from_slice(&[0x48, 0x31, 0xC0]);

    code.extend_from_slice(&[0x5F]);
    code.extend_from_slice(&[0x5E]);
    code.extend_from_slice(&[0x41, 0x5B]);
    code.extend_from_slice(&[0x41, 0x5A]);
    code.extend_from_slice(&[0x41, 0x59]);
    code.extend_from_slice(&[0x41, 0x58]);
    code.extend_from_slice(&[0x5A]);
    code.extend_from_slice(&[0x59]);
    code.extend_from_slice(&[0x58]);

    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&return_addr.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE0]);

    let buffer_small_offset = code.len();
    code[jb_buffer_small_pos] = (buffer_small_offset - jb_buffer_small_pos - 1) as u8;

    code.extend_from_slice(&[0x49, 0x89, 0x01]);

    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&0x8000000000000005u64.to_le_bytes());

    code.extend_from_slice(&[0x5F]);
    code.extend_from_slice(&[0x5E]);
    code.extend_from_slice(&[0x41, 0x5B]);
    code.extend_from_slice(&[0x41, 0x5A]);
    code.extend_from_slice(&[0x41, 0x59]);
    code.extend_from_slice(&[0x41, 0x58]);
    code.extend_from_slice(&[0x5A]);
    code.extend_from_slice(&[0x59]);
    code.extend_from_slice(&[0x58]);

    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&return_addr.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE0]);

    let no_match_offset = code.len();
    code[jne_offset_pos] = (no_match_offset - jne_offset_pos - 1) as u8;

    code.extend_from_slice(&[0x5F]);
    code.extend_from_slice(&[0x5E]);
    code.extend_from_slice(&[0x41, 0x5B]);
    code.extend_from_slice(&[0x41, 0x5A]);
    code.extend_from_slice(&[0x41, 0x59]);
    code.extend_from_slice(&[0x41, 0x58]);
    code.extend_from_slice(&[0x5A]);
    code.extend_from_slice(&[0x59]);
    code.extend_from_slice(&[0x58]);

    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&hal_efi_table_addr.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x8B, 0x00]);
    code.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
    code.extend_from_slice(&[0xFF, 0xD0]);

    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&return_addr.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE1]);

    code
}

pub fn generate_jump_to_hook(hook_addr: u64) -> [u8; 14] {
    let mut stub = [0u8; 14];
    stub[0] = 0xFF;
    stub[1] = 0x25;
    stub[2] = 0x00;
    stub[3] = 0x00;
    stub[4] = 0x00;
    stub[5] = 0x00;
    stub[6..14].copy_from_slice(&hook_addr.to_le_bytes());
    stub
}

pub fn generate_random_platform_data() -> Vec<u8> {
    let seed_path = std::path::Path::new("hwid_seed.json");
    let config = crate::hwid::SeedConfig::load(seed_path)
        .unwrap_or_else(|| crate::hwid::SeedConfig::new(rand::random()));
    let mut generator = SerialGenerator::from_config(config);
    generator.generate_random_bytes(64)
}

pub fn string_to_utf16le(s: &str) -> Vec<u8> {
    let mut result: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    result.extend_from_slice(&[0x00, 0x00]);
    result
}

pub const INLINE_HOOK_PATTERN: [u8; 9] = [0x48, 0x8B, 0x40, 0x18, 0xFF, 0xD0, 0x0F, 0x1F, 0x00];
