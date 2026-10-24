/* cross-reference (XREF) indexing engine for binary analysis */

use crate::arch::disassemble_slice;
use crate::elf::ElfBinary;
use iced_x86::{Code, FlowControl, Formatter, IntelFormatter};
use rayon::prelude::*;
use std::collections::HashMap;

/* classification of cross-reference relationship */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    DataRead,
    AddressLoad,
}

impl XrefKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            XrefKind::Call => "CALL",
            XrefKind::Jump => "JUMP",
            XrefKind::DataRead => "READ",
            XrefKind::AddressLoad => "ADDR",
        }
    }
}

/* single cross-reference site pointing to a target address */
#[derive(Debug, Clone)]
pub struct XrefEntry {
    pub source_va: u64,
    pub source_file_offset: usize,
    pub target_va: u64,
    pub kind: XrefKind,
    pub caller_func: String,
    pub caller_offset: u64,
    pub disasm: String,
}

/* index mapping target Virtual Addresses (VA) to all incoming references */
#[derive(Debug, Clone, Default)]
pub struct XrefMap {
    pub target_to_xrefs: HashMap<u64, Vec<XrefEntry>>,
}

impl XrefMap {
    pub fn new() -> Self {
        Self {
            target_to_xrefs: HashMap::new(),
        }
    }

    /* add an incoming reference entry */
    pub fn add_xref(&mut self, target_va: u64, entry: XrefEntry) {
        self.target_to_xrefs
            .entry(target_va)
            .or_default()
            .push(entry);
    }

    /* query all incoming references to a given target Virtual Address (VA) */
    pub fn get_xrefs(&self, target_va: u64) -> Option<&Vec<XrefEntry>> {
        self.target_to_xrefs.get(&target_va)
    }

    /* count incoming references */
    pub fn xref_count(&self, target_va: u64) -> usize {
        self.target_to_xrefs
            .get(&target_va)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /* safely merge another XrefMap chunk into this index */
    pub fn merge(&mut self, other: XrefMap) {
        for (target_va, entries) in other.target_to_xrefs {
            self.target_to_xrefs
                .entry(target_va)
                .or_default()
                .extend(entries);
        }
    }

    /*
     * index all executable sections (SHF_EXECINSTR) in the ELF binary using Rayon par_iter().
     * Identifies branches, calls, RIP-relative memory loads, and PLT/GOT trampolines.
     */
    pub fn build_from_elf(elf: &ElfBinary) -> Self {
        let functions = elf.find_function_symbols();

        /* helper to locate enclosing function name and relative offset for an address */
        let find_enclosing_function = |va: u64| -> (String, u64) {
            for func in &functions {
                let start = func.st_value;
                let end = func.st_value + func.st_size;
                if va >= start && va < end {
                    return (func.name.clone(), va - start);
                }
            }
            ("sub_unknown".to_string(), 0)
        };

        /* build lookup table from GOT slot VA to dynamic symbol VA */
        let mut got_to_dynsym_va = HashMap::new();
        for reloc in &elf.relocations {
            if reloc.is_plt {
                if let Some(ref sym_name) = reloc.sym_name {
                    if let Some(sym) = elf.find_symbol_by_name(sym_name) {
                        got_to_dynsym_va.insert(reloc.r_offset, sym.st_value);
                    }
                }
            }
        }

        /* filter executable sections for multi-core parallel analysis */
        let exec_sections: Vec<&crate::elf::SectionInfo> = elf
            .sections
            .iter()
            .filter(|s| s.is_executable && s.sh_size > 0 && (s.sh_offset + s.sh_size) as usize <= elf.bytes.len())
            .collect();

        /* parallelize instruction decoding and XREF indexing across executable sections */
        exec_sections
            .par_iter()
            .map(|sec| {
                let mut local_map = XrefMap::new();
                let mut formatter = IntelFormatter::new();

                let start_off = sec.sh_offset as usize;
                let end_off = (sec.sh_offset + sec.sh_size) as usize;
                let sec_bytes = &elf.bytes[start_off..end_off];
                let instructions = disassemble_slice(sec_bytes, sec.sh_addr, start_off);

                for dec_instr in instructions {
                    let instr = &dec_instr.instruction;
                    let ip = dec_instr.va;
                    let (caller_name, caller_off) = find_enclosing_function(ip);

                    let mut disasm_buf = String::new();
                    formatter.format(instr, &mut disasm_buf);

                    /* (a) near branches and calls */
                    let flow = instr.flow_control();
                    match flow {
                        FlowControl::Call => {
                            let target = instr.near_branch_target();
                            if target != 0 {
                                local_map.add_xref(
                                    target,
                                    XrefEntry {
                                        source_va: ip,
                                        source_file_offset: dec_instr.file_offset,
                                        target_va: target,
                                        kind: XrefKind::Call,
                                        caller_func: caller_name.clone(),
                                        caller_offset: caller_off,
                                        disasm: disasm_buf.clone(),
                                    },
                                );
                            }
                        }
                        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                            let target = instr.near_branch_target();
                            if target != 0 {
                                local_map.add_xref(
                                    target,
                                    XrefEntry {
                                        source_va: ip,
                                        source_file_offset: dec_instr.file_offset,
                                        target_va: target,
                                        kind: XrefKind::Jump,
                                        caller_func: caller_name.clone(),
                                        caller_offset: caller_off,
                                        disasm: disasm_buf.clone(),
                                    },
                                );
                            }
                        }
                        _ => {}
                    }

                    /* (b) RIP-relative memory operands */
                    if instr.is_ip_rel_memory_operand() {
                        let target_va = instr.ip_rel_memory_address();
                        let code = instr.code();
                        let kind = if code == Code::Lea_r64_m {
                            XrefKind::AddressLoad
                        } else if flow == FlowControl::IndirectCall {
                            XrefKind::Call
                        } else if flow == FlowControl::IndirectBranch {
                            XrefKind::Jump
                        } else {
                            XrefKind::DataRead
                        };

                        local_map.add_xref(
                            target_va,
                            XrefEntry {
                                source_va: ip,
                                source_file_offset: dec_instr.file_offset,
                                target_va,
                                kind,
                                caller_func: caller_name.clone(),
                                caller_offset: caller_off,
                                disasm: disasm_buf.clone(),
                            },
                        );

                        if let Some(&sym_va) = got_to_dynsym_va.get(&target_va) {
                            if sym_va != 0 {
                                local_map.add_xref(
                                    sym_va,
                                    XrefEntry {
                                        source_va: ip,
                                        source_file_offset: dec_instr.file_offset,
                                        target_va: sym_va,
                                        kind: XrefKind::Call,
                                        caller_func: caller_name.clone(),
                                        caller_offset: caller_off,
                                        disasm: disasm_buf.clone(),
                                    },
                                );
                            }
                        }
                    }
                }

                local_map
            })
            .reduce(XrefMap::new, |mut acc, local| {
                acc.merge(local);
                acc
            })
    }
}
