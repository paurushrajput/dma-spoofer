# DMA HWID Spoofer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2011-blue.svg)
![Stars](https://img.shields.io/github/stars/vibheksoni/dma-spoofer?style=social)
![Forks](https://img.shields.io/github/forks/vibheksoni/dma-spoofer?style=social)

> The first open-source DMA-based HWID spoofer. Spoof hardware identifiers via direct memory access using Rust and memprocfs.

Modify hardware IDs at a level below the operating system by leveraging DMA devices to read and write directly to physical memory through PCIe, bypassing CPU and OS protections entirely.

## Project Structure

```
src/
├── main.rs
├── core/
│   ├── dma.rs              # DMA engine interface (memprocfs)
│   ├── dse/                # Driver Signature Enforcement patcher
│   └── patchguard/         # PatchGuard bypass
├── hwid/
│   ├── generator.rs        # HWID generation engine
│   ├── manufacturers.rs    # Manufacturer databases
│   ├── oui.rs              # OUI MAC prefix data
│   └── patterns.rs         # Serial number patterns
├── spoofers/
│   ├── arp/                # ARP cache spoofing
│   ├── boot/               # Boot configuration spoofing
│   ├── disk/               # Disk serial spoofing (NVME/RAID/CLASSPNP)
│   ├── efi/                # EFI variable spoofing
│   ├── gpu/                # NVIDIA GPU UUID spoofing
│   ├── monitor/            # Monitor EDID spoofing (DXGKRNL)
│   ├── nic/                # NIC MAC address spoofing (Intel WiFi)
│   ├── registry/           # Registry trace cleanup
│   ├── smbios/             # SMBIOS table spoofing
│   ├── tpm/                # TPM spoofing
│   ├── usb/                # USB device ID spoofing
│   └── volume/             # Volume serial spoofing
└── utils/
    ├── codecave.rs         # Code cave injection
    ├── random.rs           # Random generation
    ├── registry.rs         # Registry helpers
    └── signature.rs        # Signature scanning
```

## Requirements

- DMA-capable hardware (FPGA PCIe device)
- Windows 11 Pro (Build 26100) - tested and built on this version
- Rust toolchain (latest stable)

**Note:** This software was only tested and built on Windows 11 Pro Build 26100. It may not work stably on other Windows versions. If you want to add support for other versions, feel free to submit a PR.

## Prerequisites

The following DLLs are required and must be placed in the same directory as the compiled binary:

| DLL | Source | Description |
|-----|--------|-------------|
| `vmm.dll` | [MemProcFS](https://github.com/ufrisk/MemProcFS/releases) | Core memory process file system library |
| `leechcore.dll` | [MemProcFS](https://github.com/ufrisk/MemProcFS/releases) | Memory acquisition library (bundled with MemProcFS) |
| `FTD3XX.dll` | [FTDI](https://ftdichip.com/drivers/d3xx-drivers/) | USB3 driver for FPGA communication |

**Setup:**
1. Download the latest [MemProcFS release](https://github.com/ufrisk/MemProcFS/releases) from ufrisk's GitHub
2. Extract `vmm.dll` and `leechcore.dll` from the release
3. Download `FTD3XX.dll` from [FTDI's D3XX driver page](https://ftdichip.com/drivers/d3xx-drivers/)
4. Place all three DLLs next to `dma-spoofer.exe`

## Building

```bash
git clone https://github.com/vibheksoni/dma-spoofer.git
cd dma-spoofer
cargo build --release
```

The compiled binary will be in `target/release/dma-spoofer.exe`.

## Spoofing Modules

### Core
- **DMA Engine** - Direct memory access interface using memprocfs
- **PatchGuard Bypass** - Disables Windows kernel protection
- **DSE Patcher** - Patches Driver Signature Enforcement

### Hardware Spoofers
| Module | Target | Details |
|--------|--------|---------|
| SMBIOS | System Management BIOS | Board, system, chassis serials |
| Disk | Hard drive serials | NVME, RAID, CLASSPNP drivers |
| GPU | NVIDIA GPU | UUID and identifiers |
| NIC | Network adapters | MAC addresses, Intel WiFi support |
| Monitor | Display EDID | Via DXGKRNL |
| Volume | Disk volumes | Volume serial numbers |
| USB | USB devices | Device identifiers |
| TPM | Trusted Platform Module | TPM identity spoofing |
| EFI | EFI variables | Boot configuration |
| Boot | Boot config | BCD data |
| ARP | ARP cache | Cache manipulation |
| Registry | Windows registry | Trace cleanup |

### Utilities
- **HWID Generator** - Generates realistic hardware IDs with manufacturer OUI patterns
- **Code Cave** - Memory injection via code cave discovery
- **Signature Scanner** - Pattern scanning in kernel memory
- **Registry Tools** - Registry manipulation helpers

## ⚠️ Stability Warning

**CRITICAL: Some modules are highly unstable and can cause system crashes (BSOD).**

The following modules directly modify kernel memory and Windows protection mechanisms. Use with extreme caution:

- **PatchGuard Bypass** - Modifies kernel protection, high risk of BSOD
- **DSE Patcher** - Patches driver signature checks, can crash system
- **TPM Spoofer** - Low-level TPM manipulation, unstable on some systems
- **EFI Spoofer** - Modifies EFI variables, can brick boot configuration

**Recommendation:** Test on a virtual machine or system you can afford to reinstall. Always have backups before running any spoofing operations.

## Educational Purpose & Legal Disclaimer

**THIS SOFTWARE IS FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

This project exists to demonstrate the capabilities and potential security implications of DMA devices. It shows how much control DMA provides over a system when proper protections are disabled - essentially allowing unrestricted access to system memory and hardware.

By using this software, you acknowledge that:
- You are using it solely for learning and understanding DMA technology
- You will not use it for any malicious, illegal, or unauthorized purposes
- You understand the security risks associated with DMA devices
- The author is not responsible for any misuse or damage caused by this software

**Use at your own risk. Modifying hardware identifiers may violate terms of service, warranties, or local laws.**

## How it Works

DMA devices can read and write directly to system memory, bypassing the CPU and operating system protections. This project leverages that capability to:

1. Access physical memory through PCIe
2. Locate hardware identifier structures
3. Modify values in real-time
4. Persist changes across reboots (depending on configuration)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

If you found this project useful or learned something from it, consider giving it a star. It helps others discover it.

## License

MIT

## Author

[vibheksoni](https://github.com/vibheksoni)

Currently open to work. If you're looking for someone with security research, browser automation, reverse engineering, or full-stack development experience - hit me up.

- X/Twitter: [@ImVibhek](https://x.com/ImVibhek)
- Website: [vibheksoni.com](https://vibheksoni.com/)
- GitHub: [vibheksoni](https://github.com/vibheksoni)

---

*Remember: With great power comes great responsibility. DMA is a powerful tool - use it wisely.*
