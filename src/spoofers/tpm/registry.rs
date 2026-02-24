use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use memprocfs::Vmm;

use super::offsets::{EK_PUB_HASH_VALUE, EK_PUB_VALUE, TPM_ENDORSEMENT_PATH};
use crate::hwid::{SeedConfig, SerialGenerator};

pub struct TpmRegistrySpoofer<'a> {
    vmm: &'a Vmm<'a>,
    original_ek_pub: Option<Vec<u8>>,
    original_ek_hash: Option<Vec<u8>>,
}

impl<'a> TpmRegistrySpoofer<'a> {
    pub fn new(vmm: &'a Vmm<'a>) -> Self {
        Self {
            vmm,
            original_ek_pub: None,
            original_ek_hash: None,
        }
    }

    fn reg_path_to_vfs(&self, reg_path: &str) -> String {
        reg_path
            .replace("HKLM\\", "/registry/HKLM/")
            .replace("\\", "/")
    }

    fn write_binary(&self, path: &str, data: &[u8]) {
        let vfs_path = self.reg_path_to_vfs(path);
        self.vmm.vfs_write(&vfs_path, data.to_vec(), 0);
    }

    pub fn list(&self) -> Result<()> {
        println!("[*] Reading TPM registry values...");

        let hklm = format!("HKLM\\{}", TPM_ENDORSEMENT_PATH);

        match self.vmm.reg_key(&hklm) {
            Ok(key) => {
                println!("    Found TPM Endorsement key");

                if let Ok(values) = key.values() {
                    for value in values {
                        if let Ok(raw) = value.raw_value() {
                            let data_preview = if raw.len() > 32 {
                                format!("{:02X?}... ({} bytes)", &raw[..32], raw.len())
                            } else {
                                format!("{:02X?}", raw)
                            };
                            println!("    {} = {}", value.name, data_preview);
                        }
                    }
                }
            }
            Err(e) => {
                println!("    TPM Endorsement key not found: {}", e);
                println!("    This may indicate TPM EK has not been cached yet");
            }
        }

        Ok(())
    }

    pub fn backup_values(&mut self) -> Result<()> {
        println!("[*] Backing up original TPM registry values...");

        let hklm = format!("HKLM\\{}", TPM_ENDORSEMENT_PATH);

        let key = self
            .vmm
            .reg_key(&hklm)
            .map_err(|e| anyhow!("Failed to open TPM Endorsement key: {}", e))?;

        if let Ok(values) = key.values() {
            for value in values {
                if let Ok(raw) = value.raw_value() {
                    match value.name.as_str() {
                        n if n == EK_PUB_VALUE => {
                            println!("    Backed up {} ({} bytes)", EK_PUB_VALUE, raw.len());
                            self.original_ek_pub = Some(raw.to_vec());
                        }
                        n if n == EK_PUB_HASH_VALUE => {
                            println!("    Backed up {} ({} bytes)", EK_PUB_HASH_VALUE, raw.len());
                            self.original_ek_hash = Some(raw.to_vec());
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    pub fn spoof(&mut self) -> Result<()> {
        println!("[*] Spoofing TPM registry values...");

        let _ = self.backup_values();

        let hklm = format!("HKLM\\{}", TPM_ENDORSEMENT_PATH);

        let fake_ek_pub = generate_fake_ek_pub();
        let fake_ek_hash = generate_fake_hash();

        println!("    Writing spoofed EKpub ({} bytes)...", fake_ek_pub.len());
        self.write_binary(&format!("{}\\{}", hklm, EK_PUB_VALUE), &fake_ek_pub);

        println!(
            "    Writing spoofed EKpubHash ({} bytes)...",
            fake_ek_hash.len()
        );
        self.write_binary(&format!("{}\\{}", hklm, EK_PUB_HASH_VALUE), &fake_ek_hash);

        println!("[+] TPM registry values spoofed");

        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        println!("[*] Clearing TPM registry values...");

        let hklm = format!("HKLM\\{}", TPM_ENDORSEMENT_PATH);

        let empty_pub = vec![0u8; 4];
        let empty_hash = vec![0u8; 32];

        println!("    Clearing EKpub...");
        self.write_binary(&format!("{}\\{}", hklm, EK_PUB_VALUE), &empty_pub);

        println!("    Clearing EKpubHash...");
        self.write_binary(&format!("{}\\{}", hklm, EK_PUB_HASH_VALUE), &empty_hash);

        println!("[+] TPM registry values cleared");

        Ok(())
    }

    pub fn restore(&self) -> Result<()> {
        println!("[*] Restoring original TPM registry values...");

        let hklm = format!("HKLM\\{}", TPM_ENDORSEMENT_PATH);

        if let Some(ref ek_pub) = self.original_ek_pub {
            println!("    Restoring EKpub ({} bytes)...", ek_pub.len());
            self.write_binary(&format!("{}\\{}", hklm, EK_PUB_VALUE), ek_pub);
        }

        if let Some(ref ek_hash) = self.original_ek_hash {
            println!("    Restoring EKpubHash ({} bytes)...", ek_hash.len());
            self.write_binary(&format!("{}\\{}", hklm, EK_PUB_HASH_VALUE), ek_hash);
        }

        println!("[+] TPM registry values restored");

        Ok(())
    }
}

fn generate_fake_ek_pub() -> Vec<u8> {
    let seed_path = Path::new("hwid_seed.json");
    let config = SeedConfig::load(seed_path).unwrap_or_else(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        SeedConfig::new(seed)
    });

    let mut generator = SerialGenerator::from_config(config);

    let mut blob = Vec::with_capacity(280);

    blob.extend_from_slice(&[0x01, 0x16]);
    blob.extend_from_slice(&[0x00, 0x01]);
    blob.extend_from_slice(&[0x00, 0x0B]);
    blob.extend_from_slice(&[0x00, 0x03, 0x00, 0x72]);
    blob.extend_from_slice(&[0x00, 0x00]);
    blob.extend_from_slice(&[0x00, 0x06]);
    blob.extend_from_slice(&[0x00, 0x80]);
    blob.extend_from_slice(&[0x00, 0x43]);
    blob.extend_from_slice(&[0x00, 0x10]);
    blob.extend_from_slice(&[0x08, 0x00]);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    blob.extend_from_slice(&[0x01, 0x00]);

    let random_modulus = generator.generate_random_bytes(256);
    blob.extend_from_slice(&random_modulus);

    if blob.len() >= 280 {
        blob[24] |= 0x80;
        blob[279] |= 0x01;
    }

    if let Err(e) = generator.to_config().save(seed_path) {
        println!("[!] Failed to save seed config: {}", e);
    }

    blob
}

fn generate_fake_hash() -> Vec<u8> {
    let seed_path = Path::new("hwid_seed.json");
    let config = SeedConfig::load(seed_path).unwrap_or_else(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        SeedConfig::new(seed)
    });

    let mut generator = SerialGenerator::from_config(config);
    let hash = generator.generate_random_bytes(32);

    if let Err(e) = generator.to_config().save(seed_path) {
        println!("[!] Failed to save seed config: {}", e);
    }

    hash
}
