use anyhow::{anyhow, Result};
use memprocfs::{Vmm, VmmProcess};

const KERNEL_PID: u32 = 4;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
const CODECAVE_ALIGNMENT: u64 = 0x10;
const MIN_CODECAVE_SIZE: usize = 0x100;
const MAX_CODECAVE_SCAN: usize = 0x1000;

const PATCHGUARD_PROTECTED: &[&str] = &[
    "ntoskrnl.exe",
    "ntkrnlmp.exe",
    "ntkrnlpa.exe",
    "ntkrpamp.exe",
    "hal.dll",
    "ksecdd.sys",
    "cng.sys",
    "ndis.sys",
    "tcpip.sys",
    "fltmgr.sys",
    "clipsp.sys",
    "clfs.sys",
    "tm.sys",
    "pshed.dll",
    "kdcom.dll",
    "bootvid.dll",
    "winload.exe",
    "hvloader.dll",
];

const SAFE_MODULES: &[&str] = &[
    "Beep.SYS",
    "Null.SYS",
    "swenum.sys",
    "umbus.sys",
    "rdpbus.sys",
    "mssmbios.sys",
    "acpiex.sys",
    "intelppm.sys",
    "amdppm.sys",
    "compbatt.sys",
    "msisadrv.sys",
    "vdrvroot.sys",
    "volmgr.sys",
    "mountmgr.sys",
    "BasicRender.sys",
];

const DISCARDABLE_SECTIONS: &[&str] = &[
    "INIT", "INITDATA", ".INIT", "PAGE", "PAGEDATA", ".PAGE", "PAGELK", "PAGEVRFY", "PAGESPEC",
    "PAGESRP0", "PAGESRP1", "PAGESRP2",
];

#[derive(Debug, Clone)]
pub struct CodecaveInfo {
    pub address: u64,
    pub size: usize,
    pub module_name: String,
    pub section_name: String,
    pub is_rwx: bool,
    pub quality_score: u32,
}

#[derive(Debug, Clone)]
struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CodecaveStrategy {
    RwxOnly,
    RxWithDma,
    Any,
}

pub struct CodecaveFinder<'a> {
    vmm: &'a Vmm<'a>,
    strategy: CodecaveStrategy,
    min_size: usize,
}

impl<'a> CodecaveFinder<'a> {
    pub fn new(vmm: &'a Vmm<'a>, strategy: CodecaveStrategy, min_size: usize) -> Self {
        Self {
            vmm,
            strategy,
            min_size: min_size.max(MIN_CODECAVE_SIZE),
        }
    }

    pub fn find_best(&self) -> Result<CodecaveInfo> {
        let process = self
            .vmm
            .process_from_pid(KERNEL_PID)
            .map_err(|e| anyhow!("Failed to get kernel process: {}", e))?;

        for &module_name in SAFE_MODULES {
            if let Ok(cave) = self.find_in_module(&process, module_name) {
                return Ok(cave);
            }
        }

        let modules = process
            .map_module(false, false)
            .map_err(|e| anyhow!("Failed to enumerate kernel modules: {}", e))?;

        let mut best_cave: Option<CodecaveInfo> = None;

        for module in modules.iter() {
            if self.is_module_blacklisted(&module.name) {
                continue;
            }

            if let Ok(caves) = self.find_all_in_module(&process, &module.name) {
                for cave in caves {
                    if best_cave.is_none()
                        || cave.quality_score > best_cave.as_ref().unwrap().quality_score
                    {
                        best_cave = Some(cave);
                    }
                }
            }
        }

        best_cave.ok_or_else(|| {
            anyhow!(
                "No suitable codecave found (min size: {} bytes, strategy: {:?})",
                self.min_size,
                self.strategy
            )
        })
    }

    pub fn find_in_module(&self, process: &VmmProcess, module_name: &str) -> Result<CodecaveInfo> {
        if self.is_module_blacklisted(module_name) {
            return Err(anyhow!("Module '{}' is blacklisted", module_name));
        }

        let module_base = process
            .get_module_base(module_name)
            .map_err(|e| anyhow!("Failed to get module base for '{}': {}", module_name, e))?;

        let sections = self.get_module_sections(process, module_name)?;

        for section in &sections {
            if !self.is_section_suitable(section) {
                continue;
            }

            if let Some(cave) =
                self.find_cave_in_section(process, module_base, module_name, section)?
            {
                return Ok(cave);
            }
        }

        Err(anyhow!("No suitable codecave found in '{}'", module_name))
    }

    fn find_all_in_module(
        &self,
        process: &VmmProcess,
        module_name: &str,
    ) -> Result<Vec<CodecaveInfo>> {
        let module_base = process
            .get_module_base(module_name)
            .map_err(|e| anyhow!("Failed to get module base for '{}': {}", module_name, e))?;

        let sections = self.get_module_sections(process, module_name)?;
        let mut codecaves = Vec::new();

        for section in &sections {
            if !self.is_section_suitable(section) {
                continue;
            }

            if let Some(cave) =
                self.find_cave_in_section(process, module_base, module_name, section)?
            {
                codecaves.push(cave);
            }
        }

        Ok(codecaves)
    }

    fn is_module_blacklisted(&self, module_name: &str) -> bool {
        PATCHGUARD_PROTECTED
            .iter()
            .any(|b| module_name.eq_ignore_ascii_case(b))
    }

    fn is_section_suitable(&self, section: &SectionInfo) -> bool {
        if DISCARDABLE_SECTIONS
            .iter()
            .any(|s| section.name.eq_ignore_ascii_case(s))
        {
            return false;
        }

        if (section.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
            return false;
        }

        let is_executable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_readable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
        let is_writable = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if !is_executable || !is_readable {
            return false;
        }

        match self.strategy {
            CodecaveStrategy::RwxOnly => is_writable,
            CodecaveStrategy::RxWithDma => true,
            CodecaveStrategy::Any => true,
        }
    }

    fn find_cave_in_section(
        &self,
        process: &VmmProcess,
        module_base: u64,
        module_name: &str,
        section: &SectionInfo,
    ) -> Result<Option<CodecaveInfo>> {
        let section_end = section.virtual_address + section.virtual_size;
        let page_boundary = (section_end + 0xFFF) & !0xFFF;
        let potential_size = (page_boundary - section_end) as usize;

        if potential_size < self.min_size {
            return Ok(None);
        }

        let cave_addr = module_base
            + section.virtual_address as u64
            + section.virtual_size as u64
            + CODECAVE_ALIGNMENT;

        let scan_size = potential_size.min(MAX_CODECAVE_SCAN);
        let actual_size = self.calculate_codecave_size(process, cave_addr, scan_size)?;

        if actual_size < self.min_size {
            return Ok(None);
        }

        let is_rwx = (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        let quality_score = self.calculate_quality_score(module_name, section, actual_size, is_rwx);

        Ok(Some(CodecaveInfo {
            address: cave_addr,
            size: actual_size,
            module_name: module_name.to_string(),
            section_name: section.name.clone(),
            is_rwx,
            quality_score,
        }))
    }

    fn get_module_sections(
        &self,
        process: &VmmProcess,
        module_name: &str,
    ) -> Result<Vec<SectionInfo>> {
        let sections = process
            .map_module_section(module_name)
            .map_err(|e| anyhow!("Failed to get sections for '{}': {}", module_name, e))?;

        Ok(sections
            .iter()
            .map(|s| SectionInfo {
                name: s.name.clone(),
                virtual_address: s.virtual_address,
                virtual_size: s.misc_virtual_size,
                characteristics: s.characteristics,
            })
            .collect())
    }

    fn calculate_codecave_size(
        &self,
        process: &VmmProcess,
        addr: u64,
        max_size: usize,
    ) -> Result<usize> {
        let data = process
            .mem_read(addr, max_size)
            .map_err(|e| anyhow!("Failed to read codecave at 0x{:X}: {}", addr, e))?;

        Ok(data.iter().take_while(|&&b| b == 0).count())
    }

    fn calculate_quality_score(
        &self,
        module_name: &str,
        section: &SectionInfo,
        size: usize,
        is_rwx: bool,
    ) -> u32 {
        let mut score: u32 = 0;

        if SAFE_MODULES
            .iter()
            .any(|s| module_name.eq_ignore_ascii_case(s))
        {
            score += 100;
        }

        if is_rwx {
            score += 50;
        }

        if section.name == ".text" || section.name == "CODE" {
            score += 30;
        }

        score += (size / 64).min(50) as u32;

        if (section.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 {
            score += 20;
        }

        score
    }

    pub fn scan_and_display(&self, min_size: usize) {
        println!(
            "[*] Scanning kernel modules for codecaves (min size: {} bytes)...",
            min_size
        );
        println!("    Strategy: {:?}", self.strategy);
        println!();

        let process = match self.vmm.process_from_pid(KERNEL_PID) {
            Ok(p) => p,
            Err(e) => {
                println!("[-] Failed to get kernel process: {}", e);
                return;
            }
        };

        let modules = match process.map_module(false, false) {
            Ok(m) => m,
            Err(e) => {
                println!("[-] Failed to enumerate kernel modules: {}", e);
                return;
            }
        };

        let mut codecaves = Vec::new();

        for module in modules.iter() {
            if self.is_module_blacklisted(&module.name) {
                continue;
            }

            if let Ok(caves) = self.find_all_in_module(&process, &module.name) {
                codecaves.extend(caves);
            }
        }

        codecaves.sort_by(|a, b| b.quality_score.cmp(&a.quality_score));

        if codecaves.is_empty() {
            println!(
                "[-] No codecaves found with minimum size of {} bytes",
                min_size
            );
            return;
        }

        println!(
            "{:<30} {:<10} {:<18} {:<8} {:<6} {:<6}",
            "Module", "Section", "Address", "Size", "RWX", "Score"
        );
        println!("{}", "-".repeat(85));

        for cave in &codecaves {
            println!(
                "{:<30} {:<10} 0x{:016X} {:<8} {:<6} {:<6}",
                cave.module_name,
                cave.section_name,
                cave.address,
                cave.size,
                if cave.is_rwx { "Yes" } else { "No" },
                cave.quality_score
            );
        }

        println!();
        println!("[+] Found {} codecaves total", codecaves.len());

        if let Some(best) = codecaves.first() {
            println!(
                "[+] Best candidate: {} ({}) at 0x{:X} ({} bytes, score: {})",
                best.module_name, best.section_name, best.address, best.size, best.quality_score
            );
        }
    }
}

pub fn find_best_codecave(vmm: &Vmm<'_>, required_size: usize) -> Result<CodecaveInfo> {
    let finder = CodecaveFinder::new(vmm, CodecaveStrategy::RxWithDma, required_size);
    finder.find_best()
}

pub fn scan_and_display_codecaves(vmm: &Vmm<'_>, min_size: usize) {
    let finder = CodecaveFinder::new(vmm, CodecaveStrategy::RxWithDma, min_size);
    finder.scan_and_display(min_size);
}
