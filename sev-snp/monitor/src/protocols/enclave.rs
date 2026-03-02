/* SPDX-License-Identifier: MIT */
use crate::cpu::*;
use crate::mem::*;
use crate::*;

use x86_64::addr::*;
use core::ptr::copy_nonoverlapping;

use crate::pgtable::pgtable_map_pages_private;
use crate::pgtable::pgtable_unmap_pages; 

use core::slice;
use core::mem;
use core::mem::size_of;
use alloc::vec::Vec;
use uuid::Bytes;

// use sha3::Sha3_256;
// use sha2::{Sha512, Digest};
use alloc::string::String;
use x86_64::structures::paging::frame::PhysFrame;
use alloc::vec;
use lazy_static::lazy_static;

const SVSM_SUCCESS: u64 = 0;
const SVSM_ERR_MISMATCHED: u64 = 1;

static mut MRCHAIN:[u8; 64] = [0;64];
static mut ENTRY_FUNCTION: u64 = 0;
static mut BUFFER_KPADDR: u64 = 0;
static mut BUFFER_SIZE: u64 = 0;
static BUFFER_UVA: u64 = 0x110000;



static FLAGS_FRESHNESS:u64 = 1;




mod simple_sha512 {
    pub struct Sha512 {
        state: [u64; 8],
        buffer: [u8; 128],
        buffer_len: usize,
        bit_len: u128,
    }

    impl Sha512 {
        pub fn new() -> Self {
            Sha512 {
                state: [
                    0x6a09e667f3bcc908,
                    0xbb67ae8584caa73b,
                    0x3c6ef372fe94f82b,
                    0xa54ff53a5f1d36f1,
                    0x510e527fade682d1,
                    0x9b05688c2b3e6c1f,
                    0x1f83d9abfb41bd6b,
                    0x5be0cd19137e2179,
                ],
                buffer: [0u8; 128],
                buffer_len: 0,
                bit_len: 0,
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut data = data;
            self.bit_len += (data.len() as u128) * 8;
            while !data.is_empty() {
                let to_copy = core::cmp::min(128 - self.buffer_len, data.len());
                self.buffer[self.buffer_len..self.buffer_len + to_copy]
                    .copy_from_slice(&data[..to_copy]);
                self.buffer_len += to_copy;
                data = &data[to_copy..];
                if self.buffer_len == 128 {
                    self.process_block();
                    self.buffer_len = 0;
                }
            }
        }

        pub fn finalize(mut self) -> [u8; 64] {
            // Padding
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 112 {
                for i in self.buffer_len..128 {
                    self.buffer[i] = 0;
                }
                self.process_block();
                self.buffer_len = 0;
            }
            for i in self.buffer_len..112 {
                self.buffer[i] = 0;
            }
            let bit_len_be = self.bit_len.to_be_bytes();
            self.buffer[112..128].copy_from_slice(&bit_len_be);
            self.process_block();

            let mut out = [0u8; 64];
            for (i, v) in self.state.iter().enumerate() {
                out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
            }
            out
        }

        fn process_block(&mut self) {
            const K: [u64; 80] = [
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
            ];
            let mut w = [0u64; 80];
            for i in 0..16 {
                w[i] = u64::from_be_bytes([
                    self.buffer[i * 8],
                    self.buffer[i * 8 + 1],
                    self.buffer[i * 8 + 2],
                    self.buffer[i * 8 + 3],
                    self.buffer[i * 8 + 4],
                    self.buffer[i * 8 + 5],
                    self.buffer[i * 8 + 6],
                    self.buffer[i * 8 + 7],
                ]);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];
            for i in 0..80 {
                let S1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(S1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let S0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = S0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }
}

fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let mut hasher = simple_sha512::Sha512::new();
    hasher.update(data);
    hasher.finalize()
}







/* This function starts the enclave test program at VMPL2 with a given 
 * Virtual Machine Save Area (VMSA). In principle, this should be handled
 * entirely within SVSM, but for simplicity the VMSA is provided by the
 * kernel for now.
 */
pub unsafe fn create_enclave_test(vmsa: *mut Vmsa) {
    prints!("Creating enclave test\n");

    let apic_id: u32 = LOWER_32BITS!((*vmsa).r9()) as u32;
    let cpu_id: usize = match smp_get_cpu_id(apic_id) {
        Some(c) => c,
        None => return,
    };
    prints!("APIC ID: {apic_id}\n");
    
    let create_vmsa_gpa: PhysAddr = PhysAddr::new((*vmsa).r8());
    let create_vmsa_va: VirtAddr = match pgtable_map_pages_private(create_vmsa_gpa, VMSA_MAP_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };
    let create_vmsa: *mut Vmsa = create_vmsa_va.as_mut_ptr();
    pgtable_print_pte_va(create_vmsa_va);

    let ret: u32 = rmpadjust(create_vmsa_va.as_u64(), RMP_4K, VMSA_PAGE | VMPL::Vmpl2 as u64);
    if ret != 0 {
        vc_terminate_svsm_general();
    }
    (*vmsa).set_rax(SVSM_SUCCESS);

    let vmpl = (*create_vmsa).vmpl();
    prints!("Enclave VMSA VMPL: {vmpl}\n");
    let stack_base = (*create_vmsa).rsp();
    prints!("Enclave stack base is at: {:#0x}\n", stack_base);
    ENTRY_FUNCTION = (*create_vmsa).rip();
    prints!("Enclave entry function is at: {:#0x}\n", ENTRY_FUNCTION);
    let enclave_cr3 = (*create_vmsa).cr3();
    prints!("Enclave cr3 is {:#0x}\n",enclave_cr3);
    {
        PERCPU.set_vmsa_for(create_vmsa_gpa, VMPL::Vmpl2, cpu_id);
        prints!("Set new VMSA for VMPL2 - enclave\n");
        enclave_vc_ap_create(create_vmsa_va, apic_id);
        pgtable_unmap_pages(create_vmsa_va, PAGE_SIZE);
    }
}

unsafe fn handle_enclave_secure_copy(vmsa: *mut Vmsa) {
    prints!("Hello from the secure copy request in SVSM!\n");
    let srcaddr: u64 = (*vmsa).rcx();
    let dstaddr: u64 = (*vmsa).rdx();
    let _num_pages: u64 = (*vmsa).r8();
    let _apic_id: u32 = LOWER_32BITS!((*vmsa).r9()) as u32;

    //Map both pages into SVSM's memory
    let srcaddr_page_pa: PhysAddr = PhysAddr::new(srcaddr);
    let srcaddr_page_va: VirtAddr = match pgtable_map_pages_private(srcaddr_page_pa, 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };

    let dstaddr_page_pa: PhysAddr = PhysAddr::new(dstaddr);
    let dstaddr_page_va: VirtAddr = match pgtable_map_pages_private(dstaddr_page_pa, 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };

    //Copy page from one space to another space
    let size: u64 = 4096;
    let dstaddr: *mut u8 = dstaddr_page_va.as_mut_ptr();
    let srcaddr: *const u8 = srcaddr_page_va.as_ptr();
    copy_nonoverlapping(srcaddr, dstaddr, size as usize);

    prints!("Done with secure copy request in SVSM!\n");
    (*vmsa).set_rax(SVSM_SUCCESS);
}

// pub unsafe fn init_enclave_input_buffer(vmsa: *mut Vmsa) {
//     prints!("init_enclave_input_buffer!\n");

//     BUFFER_KPADDR = (*vmsa).rcx();
//     BUFFER_SIZE   = (*vmsa).rdx();
//     log_kpaddr    = (*vmsa).r8();

//     //buffer related

//     prints!("BUFFER_KPADDR:{:#0x} BUFFER_SIZE:{BUFFER_SIZE}\n",BUFFER_KPADDR);

//     let buffer_vmpl0_kvaddr: VirtAddr = 
//         match pgtable_map_pages_private(PhysAddr::new(BUFFER_KPADDR), BUFFER_SIZE) {
//         Ok(v) => v,
//         Err(_e) => return,
//     };
//     prints!("buffer_vmpl0_kvaddr: {:#0x}\n",buffer_vmpl0_kvaddr);

//     let buffer_vmpl0_kvaddr_ptr: *mut u8 = buffer_vmpl0_kvaddr.as_mut_ptr();
//     core::intrinsics::write_bytes(buffer_vmpl0_kvaddr_ptr, 0, BUFFER_SIZE as usize);

//     let tmp_str: &[u8] = unsafe { slice::from_raw_parts(buffer_vmpl0_kvaddr_ptr, 16 as usize) };
//     prints!("buffer info:{:?}\n",tmp_str);

//     prints!("rmp adjust start\n");
//     if rmpadjust(buffer_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_RWX | VMPL::Vmpl1 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}
//     if rmpadjust(buffer_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_RWX | VMPL::Vmpl2 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}
//     if rmpadjust(buffer_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_RWX | VMPL::Vmpl3 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}

//     pgtable_unmap_pages(buffer_vmpl0_kvaddr, BUFFER_SIZE);

//     prints!("Done with buffer related part!\n");

//     //log related

//     prints!("log phys:{:#0x}\n",log_kpaddr);

//     let log_vmpl0_kvaddr: VirtAddr = 
//         match pgtable_map_pages_private(PhysAddr::new(log_kpaddr), log_size) {
//         Ok(v) => v,
//         Err(_e) => return,
//     };
//     prints!("log_vmpl0_kvaddr: {:#0x}\n",log_vmpl0_kvaddr);

//     let log_vmpl0_kvaddr_ptr: *mut u8 = log_vmpl0_kvaddr.as_mut_ptr();
//     core::intrinsics::write_bytes(log_vmpl0_kvaddr_ptr, 68, log_size as usize);

//     if rmpadjust(log_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_R | VMPL::Vmpl1 as u64) != 0 { vc_terminate_svsm_general();}
//     if rmpadjust(log_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_R | VMPL::Vmpl2 as u64) != 0 { vc_terminate_svsm_general();}
//     if rmpadjust(log_vmpl0_kvaddr.as_u64(), RMP_4K, VMPL_R | VMPL::Vmpl3 as u64) != 0 { vc_terminate_svsm_general();}

//     pgtable_unmap_pages(log_vmpl0_kvaddr, log_size);

//     prints!("Done with init_enclave_input_buffer\n");

//     (*vmsa).set_rax(SVSM_SUCCESS);
// }

pub unsafe fn init_enclave_input_buffer(vmsa: *mut Vmsa) {

    BUFFER_SIZE   = (*vmsa).rcx();
    prints!("init_enclave_input_buffer! size:{BUFFER_SIZE}\n");

    let frame: PhysFrame;

    let buffer_frame_size: u64 = BUFFER_SIZE/PAGE_SIZE;
    prints!("buffer frame size is:{buffer_frame_size}\n");

    frame = match mem_allocate_frames(buffer_frame_size) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };
    let tmp_frame_size : u64 = frame.size();
    prints!("Allocated buffer frame: {:#0x}\n", tmp_frame_size);

    BUFFER_KPADDR = frame.start_address().as_u64();
    prints!("BUFFER_KPADDR is:{:#0x}\n",BUFFER_KPADDR);
    let buffer_kva:VirtAddr = (pgtable_pa_to_va(frame.start_address()));

    // let buffer_kva_ptr: *mut u8 = buffer_kva.as_mut_ptr();
    // core::intrinsics::write_bytes(buffer_kva_ptr, 68, BUFFER_SIZE as usize);

    // let tmp_str: &[u8] = unsafe { slice::from_raw_parts(buffer_kva_ptr, 16 as usize) };
    // prints!("buffer info:{:?}\n",tmp_str);

    prints!("rmp adjust start\n");
    let mut adjust_va : u64 = buffer_kva.as_u64();
    let adjust_va_end : u64 = adjust_va + BUFFER_SIZE;
    while adjust_va < adjust_va_end {
        prints!("rmp adjust:{:#0x}\n",adjust_va);
        if rmpadjust(adjust_va, RMP_4K, VMPL_RWX | VMPL::Vmpl1 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}
        if rmpadjust(adjust_va, RMP_4K, VMPL_RWX | VMPL::Vmpl2 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}
        if rmpadjust(adjust_va, RMP_4K, VMPL::Vmpl3 as u64) != 0 { prints!("rmpadjust failed\n"); vc_terminate_svsm_general();}

        adjust_va += PAGE_SIZE;
    }

    prints!("Done with init_enclave_input_buffer!\n");
    (*vmsa).set_rax(SVSM_SUCCESS);
    (*vmsa).set_rcx(BUFFER_KPADDR);
}

fn get_paddr_info(paddr: u64) -> Result<u64, &'static str> {
    prints!("get_paddr paddr:{:#0x}\n", paddr);
    let paddr_low = paddr & 0x0FFFFFFFFFFFF;
    let page_paddr = PhysAddr::new(paddr_low).align_down(PAGE_SIZE);
    let offset = paddr_low as u64 % PAGE_SIZE;
    let guard = match pgtable_map_pages_private(page_paddr, PAGE_SIZE) {
        Ok(g) => g,
        Err(_) => return Err("mappig error!\n"),
    };
    let vaddr = guard.as_u64() + offset;
    let ret = unsafe { *(vaddr as *const u64) };
    prints!("paddr info is:{:#0x}\n", ret);
    Ok(ret)
}

fn test_enclave_vaddr_to_paddr(cr3: u64, vaddr: u64) -> Result<u64, &'static str> {
    prints!("start test_enclave vaddr to paddr\n");
    let pml4_index = (vaddr >> 39) & 0o777;  // 9 bits
    let pdpt_index = (vaddr >> 30) & 0o777;
    let pd_index = (vaddr >> 21) & 0o777;
    let pt_index = (vaddr >> 12) & 0o777;
    let offset = vaddr & 0xfff;
    
    
    let pml4_entry_addr = cr3 + pml4_index * 8;
    prints!("test pml4_entry_addr:{:#0x}\n",pml4_entry_addr);
    let pml4_entry = get_paddr_info(pml4_entry_addr)?;
    prints!("ended\n");
    if (pml4_entry & 1) == 0 {return Err("PML4 Entry not present");}


    let pdpt_base = pml4_entry & 0x0000FFFFFFFFF000;
    let pdpt_entry_addr = pdpt_base + pdpt_index * 8;
    let pdpt_entry = get_paddr_info(pdpt_entry_addr)?;
    if (pdpt_entry & 1) == 0 {return Err("PDPT Entry not present");}

    let pd_base = pdpt_entry & 0x0000FFFFFFFFF000;
    let pd_entry_addr = pd_base + pd_index * 8;
    let pd_entry = get_paddr_info(pd_entry_addr)?;
    if (pd_entry & 1) == 0 {return Err("PD Entry not present");}

    let pt_base = pd_entry & 0x0000FFFFFFFFF000;
    let pt_entry_addr = pt_base + pt_index * 8;
    let pt_entry = get_paddr_info(pt_entry_addr)?;
    if (pt_entry & 1) == 0 {return Err("PT Entry not present");}
    let page_base = pt_entry & 0x0000FFFFFFFFF000;

    Ok(page_base + offset)
}

pub unsafe fn verify_buffer_mapping(vmsa: *mut Vmsa){
    prints!("start verify_buffer_mapping!\n");

    let test_uvaddr = (*vmsa).rcx();

    let caa_gpa_enclave: PhysAddr = unsafe { PERCPU.caa(VMPL::Vmpl2) };
    let ca_map_enclave: MapGuard = match MapGuard::new_private(caa_gpa_enclave, CAA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return,
    };

    let vmsa_gpa_enclave: PhysAddr = unsafe { PERCPU.vmsa(VMPL::Vmpl2) };
    let mut vmsa_map_enclave: MapGuard = match MapGuard::new_private(vmsa_gpa_enclave, VMSA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return,
    };

    if !vmsa_clear_efer_svme(vmsa_map_enclave.va()) {return;}

    let vmsa_enclave: &mut Vmsa = vmsa_map_enclave.as_object_mut();
    let enclave_cr3: u64 = (*vmsa_enclave).cr3();
    prints!("enclave cr3 is :{:#0x}\n", enclave_cr3);    

    match test_enclave_vaddr_to_paddr(enclave_cr3, test_uvaddr) {
        Ok(paddr) => {
            prints!("Physical address: {:#0x}\n", paddr);
            if paddr == BUFFER_KPADDR {
                prints!("Done with verify_buffer_mapping successfully!\n");
                (*vmsa).set_rax(SVSM_SUCCESS);
            }
            else {
                prints!("mismatched!\n");
                (*vmsa).set_rax(SVSM_ERR_MISMATCHED);
            }
        }
        Err(e) => prints!("Translation failed: {e}\n"),
    }

    vmsa_set_efer_svme(vmsa_map_enclave.va());
}

pub unsafe fn transfer_input_to_enclave(vmsa: *mut Vmsa){
    prints!("transfer_input_to_enclave!\n");

    let input_kpaddr: u64 = (*vmsa).rcx();
    let input_size   = (*vmsa).rdx();

    prints!("input_kpaddr:{:#0x} input_size:{input_size}\n",input_kpaddr);
    if input_size > BUFFER_SIZE {prints!("input is too large!!!\n"); return }

    let input_map_size = ((input_size+4096-1)/4096)*4096;
    prints!("input map size:{input_map_size}\n");

    let input_vmpl0_kvaddr: VirtAddr = 
        match pgtable_map_pages_private(PhysAddr::new(input_kpaddr), input_map_size) {
        Ok(v) => v,
        Err(_e) => return,
    };
    prints!("input_vmpl0_kvaddr: {:#0x}\n",input_vmpl0_kvaddr);

    prints!("BUFFER_KPADDR:{:#0x} BUFFER_SIZE:{BUFFER_SIZE}\n",BUFFER_KPADDR);
    let buffer_vmpl0_kvaddr: VirtAddr = 
        match pgtable_map_pages_private(PhysAddr::new(BUFFER_KPADDR), BUFFER_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };
    prints!("buffer_vmpl0_kvaddr: {:#0x}\n",buffer_vmpl0_kvaddr);

    let buffer_vmpl0_kvaddr_ptr_empty: *mut u8 = buffer_vmpl0_kvaddr.as_mut_ptr();
    core::intrinsics::write_bytes(buffer_vmpl0_kvaddr_ptr_empty, 0, BUFFER_SIZE as usize);

    prints!("empty the buffer!\n");
    
    //buffer: flags(freshness) | size | input_data

    let buffer_vmpl0_kvaddr_ptr: *mut u64 = buffer_vmpl0_kvaddr.as_mut_ptr();
    buffer_vmpl0_kvaddr_ptr.write(FLAGS_FRESHNESS);
    prints!("write flags!\n");

    let input_size_ptr = buffer_vmpl0_kvaddr_ptr.add(1);
    input_size_ptr.write(input_size);

    let input_data_ptr = buffer_vmpl0_kvaddr_ptr.add(2) as * mut u8; 
    copy_nonoverlapping(input_vmpl0_kvaddr.as_ptr(),input_data_ptr,input_size as usize);
    prints!("write data!\n");
    
    // let tmp_str: &[u8] = unsafe { slice::from_raw_parts(buffer_vmpl0_kvaddr_ptr as *mut u8, 64 as usize) };
    // prints!("input info:{:?}\n",tmp_str);


    prints!("copied input_to_enclave\n");

    // measurement 
    let caa_gpa_enclave: PhysAddr = unsafe { PERCPU.caa(VMPL::Vmpl2) };
    let ca_map_enclave: MapGuard = match MapGuard::new_private(caa_gpa_enclave, CAA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return,
    };

    let vmsa_gpa_enclave: PhysAddr = unsafe { PERCPU.vmsa(VMPL::Vmpl2) };
    let mut vmsa_map_enclave: MapGuard = match MapGuard::new_private(vmsa_gpa_enclave, VMSA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return,
    };

    if !vmsa_clear_efer_svme(vmsa_map_enclave.va()) {return;}

    let vmsa_enclave: &mut Vmsa = vmsa_map_enclave.as_object_mut();
    let cur_rip = (*vmsa_enclave).rip();
    prints!("Enclave current rip is: {:#0x}\n", cur_rip);
    
    let cur_offset = cur_rip - ENTRY_FUNCTION;
    prints!("current offset is :{cur_offset}\n");


    // let result = Sha512::digest(&buffer_vmpl0_kvaddr[..16]);
    // unsafe{
    //     let ptr1:*const u8  = buffer_vmpl0_kvaddr.as_ptr();
    //     let slice1 = core::slice::from_raw_parts(ptr1, 16);
    //     prints!("slice1:{:?}\n",slice1);

    //     // let result = Sha512::digest(&slice1);
    //     let result = Sha512::digest(.to_be_bytes());
    //     prints!("end\n");
    //     prints!("cur_mr:{:?}\n",result);
    // }

    // unsafe{

    //     let mut hash_buffer: Vec<u8>  = vec![0u8; 16 as usize]; 
    //     // let mut hash_buffer = vec![0u8; 16 as usize]; 
    //     prints!("start copying the msg to hash buffer!\n");
    //     let buffer_vmpl0_kvaddr_ptr_copy: *const u8 = buffer_vmpl0_kvaddr.as_ptr();
    //     copy_nonoverlapping(buffer_vmpl0_kvaddr_ptr_copy, hash_buffer.as_mut_ptr() ,16 as usize);

    //     prints!("copied buffer msg to hash buffer!\n");

    //     // let hash_buffer_bytes: Bytes = Bytes::from(hash_buffer);

    
    //     prints!("end\n");
    //     // prints!("cur_mr:{:x}\n",cur_mr);
    // }


    let hash_data: &[u8] = unsafe { slice::from_raw_parts(input_vmpl0_kvaddr.as_mut_ptr() as *mut u8, input_size as usize) };
    // prints!("input size:{input_size}\n");
    // prints!("input info:{:?}\n",hash_data);
    let result = sha512_hash(hash_data);
    // prints!("end test\n");
    // prints!("result:{:?}\n", result);

    let mut chain_input = [0u8; 128];
    chain_input[..64].copy_from_slice(&MRCHAIN);
    chain_input[64..].copy_from_slice(&result);
    MRCHAIN = sha512_hash(&chain_input);
    // prints!("MRCHAIN:{:?}\n", MRCHAIN);

    vmsa_set_efer_svme(vmsa_map_enclave.va());

    pgtable_unmap_pages(buffer_vmpl0_kvaddr, BUFFER_SIZE);
    pgtable_unmap_pages(input_vmpl0_kvaddr, input_map_size);

    prints!("transferred input to enclave!\n");
    (*vmsa).set_rax(SVSM_SUCCESS);
}