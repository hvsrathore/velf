/* code cave scanner and automated x86_64 JMP trampoline generator */

use crate::arch::encode_instruction_at_va;
use crate::elf::ElfBinary;
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction};

/* identified code cave with contiguous filler bytes */
#[derive(Debug, Clone)]
pub struct CodeCave {
    pub file_offset: usize,
    pub va: u64,
    pub capacity: usize,
    pub section_name: String,
    pub filler_byte: u8, /* 0x00 (null zero-fill) or 0x90 (NOP sled) */
}

/* composite patch description for atomic undo/redo of trampoline hooks */
#[derive(Debug, Clone)]
pub struct TrampolinePatch {
    pub orig_file_offset: usize,
    pub orig_old_bytes: Vec<u8>,
    pub orig_new_bytes: Vec<u8>,
    pub cave_file_offset: usize,
    pub cave_old_bytes: Vec<u8>,
    pub cave_new_bytes: Vec<u8>,
}

/*
 * scan ELF sections and alignment gaps for contiguous sequences of filler bytes.
 * Scans for 0x00 or 0x90 of at least min_length (defaults to 16 bytes).
 */
pub fn scan_code_caves(elf: &ElfBinary, min_length: usize) -> Vec<CodeCave> {
    let mut caves = Vec::new();
    let min_len = min_length.max(16);

    for sec in &elf.sections {
        if sec.sh_size == 0 {
            continue;
        }

        let start_off = sec.sh_offset as usize;
        let end_off = (sec.sh_offset + sec.sh_size) as usize;
        if end_off > elf.bytes.len() {
            continue;
        }

        let sec_bytes = &elf.bytes[start_off..end_off];
        let mut idx = 0;

        while idx < sec_bytes.len() {
            let b = sec_bytes[idx];
            if b == 0x00 || b == 0x90 {
                let cave_start = idx;
                while idx < sec_bytes.len() && sec_bytes[idx] == b {
                    idx += 1;
                }
                let capacity = idx - cave_start;

                if capacity >= min_len {
                    let file_offset = start_off + cave_start;
                    let va = if sec.sh_addr > 0 {
                        sec.sh_addr + cave_start as u64
                    } else {
                        elf.offset_to_va(file_offset).unwrap_or(0)
                    };

                    caves.push(CodeCave {
                        file_offset,
                        va,
                        capacity,
                        section_name: sec.name.clone(),
                        filler_byte: b,
                    });
                }
            } else {
                idx += 1;
            }
        }
    }

    caves
}

/*
 * generate an automated x86_64 JMP trampoline:
 * 1. At the original instruction site: writes an unconditional 5-byte JMP rel32 to the Code Cave,
 *    padding any remaining trailing bytes up to orig_len with 0x90 (NOP).
 * 2. Inside the Code Cave: writes the new payload bytes followed by a 5-byte JMP rel32 return jump
 *    back to the instruction immediately following the original instruction site (next_ip).
 */
pub fn generate_trampoline(
    elf: &ElfBinary,
    orig_va: u64,
    orig_len: usize,
    payload_bytes: &[u8],
    cave: &CodeCave,
) -> Result<TrampolinePatch> {
    /* minimum 5 bytes needed at original site for JMP rel32 (0xe9 disp32) */
    if orig_len < 5 {
        return Err(anyhow!(
            "original instruction site length ({} bytes) is too short for a 5-byte JMP trampoline (minimum 5 bytes required)",
            orig_len
        ));
    }

    /* calculate total required capacity in the code cave: payload + 5-byte return jump */
    let required_cave_space = payload_bytes.len() + 5;
    if required_cave_space > cave.capacity {
        return Err(anyhow!(
            "code cave capacity ({} bytes) insufficient for trampoline payload ({} bytes needed)",
            cave.capacity,
            required_cave_space
        ));
    }

    let orig_file_offset = elf.va_to_offset(orig_va)
        .ok_or_else(|| anyhow!("failed to map original instruction VA 0x{:x} to file offset", orig_va))?;

    if orig_file_offset + orig_len > elf.bytes.len() {
        return Err(anyhow!("original instruction file offset out of binary bounds"));
    }

    /* 1. Build original site patch: JMP rel32 -> cave.va */
    let jmp_to_cave = Instruction::with_branch(Code::Jmp_rel32_64, cave.va)
        .map_err(|e| anyhow!("failed to create JMP to code cave: {}", e))?;
    let mut jmp_cave_bytes = encode_instruction_at_va(&jmp_to_cave, orig_va)?;

    /* pad leftover bytes up to original instruction length with 0x90 (NOP) */
    jmp_cave_bytes.resize(orig_len, 0x90);

    let orig_old_bytes = elf.bytes[orig_file_offset..orig_file_offset + orig_len].to_vec();

    /* 2. Build code cave contents: payload_bytes + JMP rel32 -> return_va */
    let return_va = orig_va + orig_len as u64;
    let return_jmp_va = cave.va + payload_bytes.len() as u64;

    let jmp_return = Instruction::with_branch(Code::Jmp_rel32_64, return_va)
        .map_err(|e| anyhow!("failed to create return JMP: {}", e))?;
    let return_jmp_bytes = encode_instruction_at_va(&jmp_return, return_jmp_va)?;

    let mut cave_new_bytes = Vec::with_capacity(required_cave_space);
    cave_new_bytes.extend_from_slice(payload_bytes);
    cave_new_bytes.extend_from_slice(&return_jmp_bytes);

    if cave.file_offset + required_cave_space > elf.bytes.len() {
        return Err(anyhow!("code cave offset out of binary file bounds"));
    }

    let cave_old_bytes = elf.bytes[cave.file_offset..cave.file_offset + required_cave_space].to_vec();

    Ok(TrampolinePatch {
        orig_file_offset,
        orig_old_bytes,
        orig_new_bytes: jmp_cave_bytes,
        cave_file_offset: cave.file_offset,
        cave_old_bytes,
        cave_new_bytes,
    })
}
