/* parse PLT/GOT relocation tables and live dynamic function hook redirector */

use crate::elf::ElfBinary;
use anyhow::{anyhow, Result};

/* relocation entry details for PLT/GOT inspection and hooking */
#[derive(Debug, Clone)]
pub struct RelocEntry {
    pub file_offset: usize,
    pub r_offset: u64, /* Virtual Address (VA) of the .got or .got.plt slot */
    pub r_type: u32,
    pub r_type_name: String,
    pub sym_name: String,
    pub sym_va: u64,
    pub current_target_va: u64,
    pub is_plt: bool,
    pub section_name: String,
}

/* parse all dynamic relocations from .rela.plt and .rela.dyn */
pub fn parse_relocations(elf: &ElfBinary) -> Vec<RelocEntry> {
    let mut entries = Vec::new();

    for reloc in &elf.relocations {
        let got_slot_va = reloc.r_offset;
        let file_offset = elf.va_to_offset(got_slot_va).unwrap_or(0);

        let sym_name = reloc.sym_name.clone().unwrap_or_else(|| "<unknown>".to_string());
        let sym_va = elf
            .find_symbol_by_name(&sym_name)
            .map(|s| s.st_value)
            .unwrap_or(0);

        /*
         * read current 64-bit target address stored in the .got / .got.plt slot.
         * Before runtime dynamic linking, this typically points back to the PLT resolver trampoline.
         */
        let current_target_va = if file_offset + 8 <= elf.bytes.len() {
            let slice: [u8; 8] = elf.bytes[file_offset..file_offset + 8]
                .try_into()
                .unwrap_or([0; 8]);
            if elf.is_little_endian {
                u64::from_le_bytes(slice)
            } else {
                u64::from_be_bytes(slice)
            }
        } else {
            0
        };

        let sec_name = elf
            .find_section_at_offset(file_offset)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| if reloc.is_plt { ".rela.plt".to_string() } else { ".rela.dyn".to_string() });

        let type_name = format_reloc_type(reloc.r_type);

        entries.push(RelocEntry {
            file_offset,
            r_offset: got_slot_va,
            r_type: reloc.r_type,
            r_type_name: type_name,
            sym_name,
            sym_va,
            current_target_va,
            is_plt: reloc.is_plt,
            section_name: sec_name,
        });
    }

    entries
}

/*
 * redirect a dynamic function pointer by overwriting its .got or .got.plt slot.
 * Serializes the new target Virtual Address (VA) in the binary's target endianness.
 * Returns (old_bytes, new_bytes) for atomic UndoStack recording.
 */
pub fn write_hook_target(
    elf: &mut ElfBinary,
    file_offset: usize,
    new_target_va: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if file_offset + 8 > elf.bytes.len() {
        return Err(anyhow!("GOT slot offset 0x{:x} out of binary bounds", file_offset));
    }

    let old_bytes = elf.bytes[file_offset..file_offset + 8].to_vec();
    let new_bytes = if elf.is_little_endian {
        new_target_va.to_le_bytes().to_vec()
    } else {
        new_target_va.to_be_bytes().to_vec()
    };

    elf.bytes[file_offset..file_offset + 8].copy_from_slice(&new_bytes);
    Ok((old_bytes, new_bytes))
}

/* format x86_64 relocation types into symbolic names */
pub fn format_reloc_type(r_type: u32) -> String {
    match r_type {
        1 => "R_X86_64_64".to_string(),
        2 => "R_X86_64_PC32".to_string(),
        3 => "R_X86_64_GOT32".to_string(),
        4 => "R_X86_64_PLT32".to_string(),
        5 => "R_X86_64_COPY".to_string(),
        6 => "R_X86_64_GLOB_DAT".to_string(),
        7 => "R_X86_64_JUMP_SLOT".to_string(),
        8 => "R_X86_64_RELATIVE".to_string(),
        9 => "R_X86_64_GOTPCREL".to_string(),
        10 => "R_X86_64_32".to_string(),
        11 => "R_X86_64_32S".to_string(),
        12 => "R_X86_64_16".to_string(),
        13 => "R_X86_64_PC16".to_string(),
        14 => "R_X86_64_8".to_string(),
        15 => "R_X86_64_PC8".to_string(),
        _ => format!("R_X86_64_TYPE_{}", r_type),
    }
}
