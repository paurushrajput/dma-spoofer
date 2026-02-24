use anyhow::Result;

use crate::core::Dma;

use super::hook::TpmDispatchHook;
use super::registry::TpmRegistrySpoofer;

pub struct TpmSpoofer<'a> {
    registry_spoofer: TpmRegistrySpoofer<'a>,
    dispatch_hook: TpmDispatchHook<'a>,
}

impl<'a> TpmSpoofer<'a> {
    pub fn new(dma: &'a Dma<'a>) -> Self {
        Self {
            registry_spoofer: TpmRegistrySpoofer::new(dma.vmm()),
            dispatch_hook: TpmDispatchHook::new(dma),
        }
    }

    pub fn list(&self) -> Result<()> {
        self.registry_spoofer.list()
    }

    pub fn spoof(&mut self) -> Result<()> {
        println!("[*] TPM Spoofer - Full Mode");

        self.registry_spoofer.spoof()?;

        println!("\n[*] Attempting to install hook...");
        self.dispatch_hook.find_tpm_driver()?;

        match self.dispatch_hook.find_rwx_codecave() {
            Ok(_) => {
                self.dispatch_hook.install()?;
                println!("[+] Hook installed - TPM responses will be intercepted");
            }
            Err(e) => {
                println!("[!] Could not install hook: {}", e);
                println!("[*] Registry-only spoof applied");
            }
        }

        Ok(())
    }

    pub fn spoof_registry_only(&mut self) -> Result<()> {
        self.registry_spoofer.spoof()
    }

    pub fn clear(&self) -> Result<()> {
        self.registry_spoofer.clear()
    }

    pub fn install_hook(&mut self) -> Result<()> {
        self.dispatch_hook.find_tpm_driver()?;
        self.dispatch_hook.find_rwx_codecave()?;
        self.dispatch_hook.install()
    }

    pub fn remove_hook(&mut self) -> Result<()> {
        self.dispatch_hook.remove()
    }

    pub fn restore(&self) -> Result<()> {
        self.registry_spoofer.restore()
    }

    pub fn is_hooked(&self) -> bool {
        self.dispatch_hook.is_hooked()
    }
}

impl<'a> Drop for TpmSpoofer<'a> {
    fn drop(&mut self) {}
}
