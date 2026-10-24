/* parallel backward-sliding ROP gadget scanning engine across multi-core CPUs */

use crate::elf::ElfBinary;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter};
use rayon::prelude::*;
use std::collections::HashSet;

/* maximum backward search window depth in bytes prior to a control-flow terminator */
pub const MAX_GADGET_BACKWARD_BYTES: usize = 16;
/* maximum instruction count allowed per ROP gadget */
pub const MAX_GADGET_INSTRUCTIONS: usize = 6;
/* chunk partition size for multi-threaded parallel scanning */
pub const PARALLEL_CHUNK_SIZE: usize = 16384;

/* single discovered return-oriented programming (ROP) gadget */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RopGadget {
    pub va: u64,
    pub file_offset: usize,
    pub bytes: Vec<u8>,
    pub instructions: Vec<String>,
    pub disasm: String,
    pub terminates_with_ret: bool,
}

/*
 * scan executable binary sections in parallel across CPU cores using Rayon.
 * Employs a backward-sliding window from control-flow terminators (RET, JMP, CALL, SYSCALL).
 */
pub fn scan_rop_gadgets_parallel(elf: &ElfBinary) -> Vec<RopGadget> {
    let mut exec_ranges = Vec::new();

    /* collect all executable sections (SHF_EXECINSTR) */
    for sec in &elf.sections {
        if sec.is_executable && sec.sh_size > 0 {
            let start = sec.sh_offset as usize;
            let end = (sec.sh_offset + sec.sh_size) as usize;
            if end <= elf.bytes.len() {
                exec_ranges.push((start, end, sec.sh_addr));
            }
        }
    }

    if exec_ranges.is_empty() {
        return Vec::new();
    }

    /* partition executable ranges into parallel work chunks */
    let mut chunks = Vec::new();
    for (start, end, base_va) in exec_ranges {
        let mut cur = start;
        while cur < end {
            let chunk_end = (cur + PARALLEL_CHUNK_SIZE).min(end);
            /* add overlap buffer so gadgets spanning chunk boundaries are captured */
            let scan_end = (chunk_end + MAX_GADGET_BACKWARD_BYTES).min(end);
            chunks.push((cur, scan_end, base_va + (cur - start) as u64));
            cur = chunk_end;
        }
    }

    /* execute multi-core parallel scan */
    let mut all_gadgets: Vec<RopGadget> = chunks
        .par_iter()
        .flat_map(|&(c_start, c_end, c_va)| {
            scan_chunk_gadgets(&elf.bytes, c_start, c_end, c_va)
        })
        .collect();

    /* deduplicate gadgets by file offset and sort by Virtual Address (VA) */
    let mut seen_offsets = HashSet::new();
    all_gadgets.retain(|g| seen_offsets.insert(g.file_offset));
    all_gadgets.sort_by_key(|g| g.va);

    all_gadgets
}

/* scan a localized byte chunk for backward-sliding ROP gadgets */
fn scan_chunk_gadgets(
    bytes: &[u8],
    chunk_start: usize,
    chunk_end: usize,
    chunk_va: u64,
) -> Vec<RopGadget> {
    let mut local_gadgets = Vec::new();
    let mut formatter = IntelFormatter::new();

    let slice_len = chunk_end.saturating_sub(chunk_start);
    if slice_len == 0 || chunk_end > bytes.len() {
        return local_gadgets;
    }

    /* scan for terminator byte positions in chunk */
    for offset_in_chunk in 0..slice_len {
        let abs_offset = chunk_start + offset_in_chunk;
        let b = bytes[abs_offset];

        /* check for RET (0xc3), RET imm16 (0xc2), or SYSCALL (0x0f 0x05) */
        let is_ret = b == 0xc3 || b == 0xc2;
        let is_syscall = b == 0x0f && abs_offset + 1 < bytes.len() && bytes[abs_offset + 1] == 0x05;

        if !is_ret && !is_syscall {
            continue;
        }

        let terminator_offset = abs_offset;
        let min_start = terminator_offset.saturating_sub(MAX_GADGET_BACKWARD_BYTES).max(chunk_start);

        /* slide backward from terminator to find valid instruction sequences */
        for start_offset in min_start..=terminator_offset {
            let va = chunk_va + (start_offset - chunk_start) as u64;
            let max_len = (terminator_offset + 3).min(bytes.len()) - start_offset;
            let candidate_bytes = &bytes[start_offset..start_offset + max_len];

            let mut decoder = Decoder::with_ip(64, candidate_bytes, va, DecoderOptions::NONE);
            let mut instrs = Vec::new();
            let mut valid = true;
            let mut ends_at_terminator = false;
            let mut terminates_with_ret = false;

            while decoder.can_decode() && instrs.len() < MAX_GADGET_INSTRUCTIONS {
                let instr = decoder.decode();
                if instr.is_invalid() || instr.code() == Code::INVALID {
                    valid = false;
                    break;
                }

                let mut disasm_buf = String::new();
                formatter.format(&instr, &mut disasm_buf);
                instrs.push(disasm_buf);

                let cur_ip = instr.ip();
                let cur_off = start_offset + (cur_ip - va) as usize;

                if cur_off == terminator_offset {
                    ends_at_terminator = true;
                    if instr.flow_control() == FlowControl::Return {
                        terminates_with_ret = true;
                    }
                    break;
                }

                if cur_off > terminator_offset {
                    /* overshot terminator byte boundary */
                    break;
                }

                if instr.flow_control() != FlowControl::Next {
                    /* mid-gadget branches invalidate linear execution */
                    valid = false;
                    break;
                }
            }

            if valid && ends_at_terminator && !instrs.is_empty() {
                let total_len = (terminator_offset + 1).saturating_sub(start_offset);
                let g_bytes = bytes[start_offset..start_offset + total_len].to_vec();
                let full_disasm = instrs.join(" ; ");

                local_gadgets.push(RopGadget {
                    va,
                    file_offset: start_offset,
                    bytes: g_bytes,
                    instructions: instrs,
                    disasm: full_disasm,
                    terminates_with_ret,
                });
            }
        }
    }

    local_gadgets
}
