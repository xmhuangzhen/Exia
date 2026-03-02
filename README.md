# EXIA: Trusted Transitions for Enclaves via External-Input Attestation

This repository contains the code for the paper ["EXIA: Trusted Transitions for Enclaves via External-Input Attestation"](https://www.ndss-symposium.org/ndss-paper/exia-trusted-transitions-for-enclaves-via-external-input-attestation/), accepted by NDSS 2026.

Exia introduces *External-Input Attestation* to attest all writes to TEE-protected applications, based on the observation that memory corruption attacks typically start with unintended writes. This approach ensures a trusted enclave state by verifying all writes match expectations, transforming security issues, such as control-flow hijacking, into reliability issues, such as a software crash due to unexpected input.


This repository includes implementations for both **AMD SEV-SNP** (based on [VEIL](https://github.com/adilahmad17/Veil)) and [**Penglai**](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM) (RISC-V) TEEs. These two implementations are independent of each other and reside in their respective directories.


## AMD SEV-SNP Implementation

### Prerequisites
- **Hardware:** AMD EPYC 4th Gen (Genoa) or later with SEV-SNP support.
- **Host OS:** Ubuntu 24.04 with kernel version `6.7.0-snp-host` (using AMD’s `svsmpreview-hv-v4` branch).
- **Guest OS:** Ubuntu 24.04 with a kernel based on version `6.8.0-snp-guest` (using AMD’s `svsm-preview-guest-v4` branch).

### Usage

#### Step 1: Set Up Host OS and Guest OS

We recommend using the [AMDSEV](https://github.com/AMDESE/AMDSEV) scripts (branch `svsm-preview`) to build and install the required components, including the host kernel, guest kernel, QEMU, and OVMF with SVSM support.

- **Host kernel:** Build from AMD's [`svsm-preview-hv-v4`](https://github.com/AMDESE/linux/tree/svsm-preview-hv-v4) branch (kernel `6.7.0-snp-host`) and install it on the host.
- **Guest kernel:** Build from AMD's [`svsm-preview-guest-v4`](https://github.com/AMDESE/linux/tree/svsm-preview-guest-v4) branch (kernel `6.8.0-snp-guest`) and install it in the guest disk image.
- **QEMU:** Build from AMD's QEMU branch with SVSM support.
- **OVMF:** Build from AMD's EDK2 fork with SNP support.

Prepare a guest disk image (e.g., `guest.qcow2`) with Ubuntu 24.04 and the SNP guest kernel installed.

#### Step 2: Build the Monitor

```bash
cd sev-snp/monitor

# Install Rust toolchain and dependencies (first time only)
make prereq

# Build the SVSM monitor binary
make
```

This produces `svsm.bin` in the `sev-snp/monitor/` directory.

#### Step 3: Launch the SEV-SNP VM with QEMU

Use the [`launch-qemu.sh`](https://github.com/AMDESE/linux-svsm/blob/main/scripts/launch-qemu.sh) script from AMD's [linux-svsm](https://github.com/AMDESE/linux-svsm) repository to start the VM:

```bash
sudo ./launch-qemu.sh -hda <your_disk.qcow2> -svsm sev-snp/monitor/svsm.bin -sev-snp
```

The script automatically configures QEMU with SEV-SNP and SVSM support. Run `./launch-qemu.sh` without arguments to see all available options.

---

## Penglai Implementation

### Prerequisites
- **Docker:** Version 28.0.1.
- **QEMU:** `qemu-system-riscv64` (version 4.1.1) instance configured with 4 GB of memory.
- **System:** This setup was based on the [Penglai-Enclave-TVM](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM) and ran on an Ubuntu 16.04 system with GCC version 5.4.

### Usage

#### Step 1: Install Docker

Install Docker (version 28.0.1 or later) on your host system.

#### Step 2: Set Up Penglai-Enclave-TVM

Clone and configure the [Penglai-Enclave-TVM](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM) repository following its instructions.

#### Step 3: Replace OpenSBI and Launch

Replace the `Penglai-Opensbi-TVM` directory in the Penglai-Enclave-TVM repository with the one provided in `penglai/Penglai-Opensbi-TVM`:

```bash
rm -rf Penglai-Opensbi-TVM
cp -r /path/to/Exia/penglai/Penglai-Opensbi-TVM .
```

Then use the [`docker_cmd.sh`](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM/blob/main/docker_cmd.sh) script to build and run Penglai in QEMU:

```bash
./docker_cmd.sh build
./docker_cmd.sh qemu
```

---

## Citation


```bibtex
@inproceedings{exia2026,
  author={Zhen Huang and Yidi Kao and Sanchuan Chen and Guoxing Chen and Yan Meng and Haojin Zhu},
  title        = {EXIA: Trusted Transitions for Enclaves via External-Input Attestation},
  booktitle    = {Network and Distributed System Security Symposium, {NDSS} 2026},
  publisher    = {The Internet Society},
  year         = {2026},
}
```
