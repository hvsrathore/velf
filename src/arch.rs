/* disassembler, x86_64 intel instruction parser, and in-place patch encoder */

use anyhow::{anyhow, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Formatter,
    FormatterOutput, FormatterTextKind, Instruction, InstructionBlock, IntelFormatter,
    MemoryOperand, Register,
};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use std::collections::HashMap;

/* precomputed static 2-hex-digit lookup table with trailing space to eliminate allocations */
pub static HEX_TABLE: [&str; 256] = [
    "00 ", "01 ", "02 ", "03 ", "04 ", "05 ", "06 ", "07 ", "08 ", "09 ", "0a ", "0b ", "0c ", "0d ", "0e ", "0f ",
    "10 ", "11 ", "12 ", "13 ", "14 ", "15 ", "16 ", "17 ", "18 ", "19 ", "1a ", "1b ", "1c ", "1d ", "1e ", "1f ",
    "20 ", "21 ", "22 ", "23 ", "24 ", "25 ", "26 ", "27 ", "28 ", "29 ", "2a ", "2b ", "2c ", "2d ", "2e ", "2f ",
    "30 ", "31 ", "32 ", "33 ", "34 ", "35 ", "36 ", "37 ", "38 ", "39 ", "3a ", "3b ", "3c ", "3d ", "3e ", "3f ",
    "40 ", "41 ", "42 ", "43 ", "44 ", "45 ", "46 ", "47 ", "48 ", "49 ", "4a ", "4b ", "4c ", "4d ", "4e ", "4f ",
    "50 ", "51 ", "52 ", "53 ", "54 ", "55 ", "56 ", "57 ", "58 ", "59 ", "5a ", "5b ", "5c ", "5d ", "5e ", "5f ",
    "60 ", "61 ", "62 ", "63 ", "64 ", "65 ", "66 ", "67 ", "68 ", "69 ", "6a ", "6b ", "6c ", "6d ", "6e ", "6f ",
    "70 ", "71 ", "72 ", "73 ", "74 ", "75 ", "76 ", "77 ", "78 ", "79 ", "7a ", "7b ", "7c ", "7d ", "7e ", "7f ",
    "80 ", "81 ", "82 ", "83 ", "84 ", "85 ", "86 ", "87 ", "88 ", "89 ", "8a ", "8b ", "8c ", "8d ", "8e ", "8f ",
    "90 ", "91 ", "92 ", "93 ", "94 ", "95 ", "96 ", "97 ", "98 ", "99 ", "9a ", "9b ", "9c ", "9d ", "9e ", "9f ",
    "a0 ", "a1 ", "a2 ", "a3 ", "a4 ", "a5 ", "a6 ", "a7 ", "a8 ", "a9 ", "aa ", "ab ", "ac ", "ad ", "ae ", "af ",
    "b0 ", "b1 ", "b2 ", "b3 ", "b4 ", "b5 ", "b6 ", "b7 ", "b8 ", "b9 ", "ba ", "bb ", "bc ", "bd ", "be ", "bf ",
    "c0 ", "c1 ", "c2 ", "c3 ", "c4 ", "c5 ", "c6 ", "c7 ", "c8 ", "c9 ", "ca ", "cb ", "cc ", "cd ", "ce ", "cf ",
    "d0 ", "d1 ", "d2 ", "d3 ", "d4 ", "d5 ", "d6 ", "d7 ", "d8 ", "d9 ", "da ", "db ", "dc ", "dd ", "de ", "df ",
    "e0 ", "e1 ", "e2 ", "e3 ", "e4 ", "e5 ", "e6 ", "e7 ", "e8 ", "e9 ", "ea ", "eb ", "ec ", "ed ", "ee ", "ef ",
    "f0 ", "f1 ", "f2 ", "f3 ", "f4 ", "f5 ", "f6 ", "f7 ", "f8 ", "f9 ", "fa ", "fb ", "fc ", "fd ", "fe ", "ff ",
];

/* precomputed static 2-hex-digit lookup table without trailing space */
pub static HEX_BYTE: [&str; 256] = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
];

/* represents a fully decoded x86_64 machine instruction */
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub va: u64,
    pub file_offset: usize,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub disasm: String,
    pub mnemonic: String,
    pub op_str: String,
    pub flow_control: FlowControl,
    pub instruction: Instruction,
    pub formatted_hex: String,
}

impl DecodedInstruction {
    /* check if instruction represents any control flow redirection (CALL, JMP, Jcc, RET) */
    pub fn is_control_flow(&self) -> bool {
        !matches!(
            self.flow_control,
            FlowControl::Next | FlowControl::Interrupt | FlowControl::Exception
        )
    }

    /* check if instruction is a conditional branch (e.g. JE, JNE, JA, JB) */
    pub fn is_conditional_branch(&self) -> bool {
        self.flow_control == FlowControl::ConditionalBranch
    }

    /* check if instruction is an unconditional branch (e.g. JMP) */
    pub fn is_unconditional_branch(&self) -> bool {
        self.flow_control == FlowControl::UnconditionalBranch
    }

    /* check if instruction is a subroutine call (CALL) */
    pub fn is_call(&self) -> bool {
        self.flow_control == FlowControl::Call || self.flow_control == FlowControl::IndirectCall
    }

    /* check if instruction is a subroutine return (RET) */
    pub fn is_return(&self) -> bool {
        self.flow_control == FlowControl::Return
    }

    /* extract direct branch/call target Virtual Address (VA) */
    pub fn near_branch_target(&self) -> Option<u64> {
        let target = self.instruction.near_branch_target();
        if target != 0 {
            Some(target)
        } else {
            None
        }
    }

    /* check if instruction accesses memory using RIP-relative addressing */
    pub fn is_ip_rel_memory(&self) -> bool {
        self.instruction.is_ip_rel_memory_operand()
    }

    /* compute RIP-relative target Virtual Address (VA) */
    pub fn ip_rel_memory_address(&self) -> Option<u64> {
        if self.instruction.is_ip_rel_memory_operand() {
            Some(self.instruction.ip_rel_memory_address())
        } else {
            None
        }
    }

    /* format instruction into styled ratatui spans according to active theme palette */
    pub fn format_spans(&self, palette: &crate::theme::Palette, is_selected: bool) -> Vec<Span<'static>> {
        if is_selected {
            let cursor_style = Style::default()
                .fg(crate::theme::to_color(palette.cursor_fg))
                .bg(crate::theme::to_color(palette.cursor_bg))
                .add_modifier(Modifier::BOLD);
            return vec![
                Span::styled(format!("{:<8} ", self.mnemonic), cursor_style),
                Span::styled(self.op_str.clone(), cursor_style),
            ];
        }

        let mut formatter = IntelFormatter::new();
        let mut output = SpanFormatterOutput::new(palette);
        formatter.format(&self.instruction, &mut output);

        /* override mnemonic styling for control flow instructions */
        if let Some(first) = output.spans.first_mut() {
            let m_col = if self.is_call() {
                palette.mnemonic_call
            } else if self.is_conditional_branch() || self.is_unconditional_branch() {
                palette.mnemonic_jump
            } else if self.is_return() {
                palette.mnemonic_ret
            } else {
                palette.mnemonic
            };
            first.style = Style::default()
                .fg(crate::theme::to_color(m_col))
                .add_modifier(Modifier::BOLD);
        }

        output.spans
    }
}

/* iced-x86 FormatterOutput that styles disassembly tokens with Theme palette */
pub struct SpanFormatterOutput<'a> {
    pub spans: Vec<Span<'static>>,
    palette: &'a crate::theme::Palette,
}

impl<'a> SpanFormatterOutput<'a> {
    pub fn new(palette: &'a crate::theme::Palette) -> Self {
        Self {
            spans: Vec::with_capacity(8),
            palette,
        }
    }
}

impl<'a> FormatterOutput for SpanFormatterOutput<'a> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let col = match kind {
            FormatterTextKind::Mnemonic => self.palette.mnemonic,
            FormatterTextKind::Register => self.palette.register,
            FormatterTextKind::Number => self.palette.immediate,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => {
                if text == "[" || text == "]" || text == "+" || text == "*" {
                    self.palette.memory_bracket
                } else {
                    self.palette.foreground
                }
            }
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => {
                self.palette.branch_target
            }
            FormatterTextKind::Keyword | FormatterTextKind::Directive => self.palette.keyword,
            _ => self.palette.foreground,
        };

        self.spans.push(Span::styled(
            text.to_string(),
            Style::default().fg(crate::theme::to_color(col)),
        ));
    }
}

/*
 * instruction cache backed by an LRU eviction policy and pre-indexed offset map.
 * Caches decoded iced-x86 instructions by file offset so cursor navigation (j/k)
 * and viewport virtualization operate in O(1) time without repeating raw byte decodes.
 */
#[derive(Debug, Clone)]
pub struct InstructionCache {
    pub capacity: usize,
    pub entries: HashMap<usize, (DecodedInstruction, u64)>,
    pub access_counter: u64,
    pub known_offsets: Vec<usize>,
}

impl InstructionCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(512),
            entries: HashMap::with_capacity(capacity.max(512)),
            access_counter: 0,
            known_offsets: Vec::new(),
        }
    }

    /* retrieve decoded instruction from cache in O(1) time */
    pub fn get(&mut self, offset: usize) -> Option<&DecodedInstruction> {
        self.access_counter += 1;
        let counter = self.access_counter;
        if let Some(entry) = self.entries.get_mut(&offset) {
            entry.1 = counter;
            Some(&entry.0)
        } else {
            None
        }
    }

    /* insert decoded instruction into cache, evicting LRU entry when at capacity */
    pub fn insert(&mut self, offset: usize, instr: DecodedInstruction) {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&offset) {
            if let Some((&lru_offset, _)) = self.entries.iter().min_by_key(|(_, (_, acc))| *acc) {
                self.entries.remove(&lru_offset);
            }
        }

        self.access_counter += 1;
        self.entries.insert(offset, (instr, self.access_counter));

        if let Err(pos) = self.known_offsets.binary_search(&offset) {
            self.known_offsets.insert(pos, offset);
        }
    }

    /* get or decode a single instruction at given offset */
    pub fn get_or_decode(
        &mut self,
        bytes: &[u8],
        offset: usize,
        va: u64,
    ) -> Option<DecodedInstruction> {
        if let Some(cached) = self.get(offset) {
            return Some(cached.clone());
        }

        if offset >= bytes.len() {
            return None;
        }

        let slice = &bytes[offset..bytes.len().min(offset + 15)];
        let mut decoder = Decoder::with_ip(64, slice, va, DecoderOptions::NONE);
        if !decoder.can_decode() {
            return None;
        }

        let instr = decoder.decode();
        let len = instr.len();
        if len == 0 || offset + len > bytes.len() {
            return None;
        }

        let instr_bytes = bytes[offset..offset + len].to_vec();
        let mut formatter = IntelFormatter::new();
        let mut disasm = String::new();
        formatter.format(&instr, &mut disasm);

        let (mnemonic, op_str) = match disasm.split_once(' ') {
            Some((m, ops)) => (m.to_string(), ops.trim().to_string()),
            None => (disasm.clone(), String::new()),
        };

        let mut formatted_hex = String::with_capacity(len * 3);
        for (i, &b) in instr_bytes.iter().enumerate() {
            if i > 0 {
                formatted_hex.push(' ');
            }
            formatted_hex.push_str(HEX_BYTE[b as usize]);
        }

        let decoded = DecodedInstruction {
            va,
            file_offset: offset,
            len,
            bytes: instr_bytes,
            disasm,
            mnemonic,
            op_str,
            flow_control: instr.flow_control(),
            instruction: instr,
            formatted_hex,
        };

        self.insert(offset, decoded.clone());
        Some(decoded)
    }

    /* locate next instruction offset in O(1) */
    pub fn next_offset(&self, offset: usize) -> Option<usize> {
        match self.known_offsets.binary_search(&offset) {
            Ok(idx) => self.known_offsets.get(idx + 1).copied(),
            Err(idx) => self.known_offsets.get(idx).copied(),
        }
    }

    /* locate previous instruction offset in O(1) */
    pub fn prev_offset(&self, offset: usize) -> Option<usize> {
        match self.known_offsets.binary_search(&offset) {
            Ok(idx) => if idx > 0 { self.known_offsets.get(idx - 1).copied() } else { None },
            Err(idx) => if idx > 0 { self.known_offsets.get(idx - 1).copied() } else { None },
        }
    }

    /* pre-populate cache from a sequence of decoded instructions */
    pub fn populate(&mut self, instructions: &[DecodedInstruction]) {
        for instr in instructions {
            self.insert(instr.file_offset, instr.clone());
        }
    }

    /* pre-index a contiguous range of instructions into the cache */
    pub fn preindex_range(
        &mut self,
        bytes: &[u8],
        start_offset: usize,
        base_va: u64,
        max_count: usize,
    ) {
        let mut cur_off = start_offset;
        let mut cur_va = base_va;
        let mut count = 0;

        while cur_off < bytes.len() && count < max_count {
            if let Some(instr) = self.get_or_decode(bytes, cur_off, cur_va) {
                let len = instr.len;
                cur_off += len;
                cur_va += len as u64;
                count += 1;
            } else {
                cur_off += 1;
                cur_va += 1;
            }
        }
    }

    /* clear cached entries upon binary patching */
    pub fn clear(&mut self) {
        self.entries.clear();
        self.known_offsets.clear();
        self.access_counter = 0;
    }
}

/*
 * disassemble a contiguous byte slice starting at given Virtual Address (VA) and file offset.
 * Uses iced-x86 in 64-bit mode with Intel syntax formatting.
 */
pub fn disassemble_slice(
    bytes: &[u8],
    base_va: u64,
    base_file_offset: usize,
) -> Vec<DecodedInstruction> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(64, bytes, base_va, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instructions = Vec::new();

    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let len = instr.len();
        let rel_off = (ip - base_va) as usize;

        if rel_off + len > bytes.len() {
            break;
        }

        let instr_bytes = bytes[rel_off..rel_off + len].to_vec();
        let mut disasm = String::new();
        formatter.format(&instr, &mut disasm);

        /* split formatted string into mnemonic and operand strings */
        let (mnemonic, op_str) = match disasm.split_once(' ') {
            Some((m, ops)) => (m.to_string(), ops.trim().to_string()),
            None => (disasm.clone(), String::new()),
        };

        let mut formatted_hex = String::with_capacity(len * 3);
        for (i, &b) in instr_bytes.iter().enumerate() {
            if i > 0 {
                formatted_hex.push(' ');
            }
            formatted_hex.push_str(HEX_BYTE[b as usize]);
        }

        instructions.push(DecodedInstruction {
            va: ip,
            file_offset: base_file_offset + rel_off,
            len,
            bytes: instr_bytes,
            disasm,
            mnemonic,
            op_str,
            flow_control: instr.flow_control(),
            instruction: instr,
            formatted_hex,
        });
    }

    instructions
}

/*
 * parse an Intel-syntax instruction string, encode it at target Virtual Address (VA)
 * using iced-x86 BlockEncoder, and enforce in-place binary safety with automatic NOP padding.
 */
pub fn parse_and_encode_instruction(
    input: &str,
    target_va: u64,
    orig_len: usize,
) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("instruction string cannot be empty"));
    }

    /* check if user provided raw hex bytes (e.g. 'raw: 90 90' or 'hex: cc' or 'db 90') */
    let raw_encoded = if let Some(hex_part) = trimmed.strip_prefix("raw:")
        .or_else(|| trimmed.strip_prefix("hex:"))
        .or_else(|| trimmed.strip_prefix("db "))
    {
        parse_hex_bytes(hex_part)?
    } else {
        /* parse typed Intel mnemonic and operands into iced_x86::Instruction */
        let instr = parse_intel_instruction(trimmed, target_va)?;
        encode_instruction_at_va(&instr, target_va)?
    };

    /*
     * enforce in-place binary safety:
     * 1. If encoded length exceeds original instruction size, abort edit to prevent code overlap.
     * 2. If shorter, write newly encoded machine code and pad remaining trailing bytes with 0x90 (NOP).
     */
    if raw_encoded.len() > orig_len {
        return Err(anyhow!(
            "patch rejected: encoded size ({} bytes) exceeds original instruction size ({} bytes)",
            raw_encoded.len(),
            orig_len
        ));
    }

    let mut final_bytes = raw_encoded;
    final_bytes.resize(orig_len, 0x90); /* automatic NOP sled padding */
    Ok(final_bytes)
}

/* encode an iced-x86 instruction struct at a given Virtual Address (VA) */
pub fn encode_instruction_at_va(instr: &Instruction, target_va: u64) -> Result<Vec<u8>> {
    let block = InstructionBlock::new(std::slice::from_ref(instr), target_va);
    let result = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| anyhow!("failed to encode instruction at 0x{:x}: {}", target_va, e))?;
    Ok(result.code_buffer)
}

/*
 * intel-syntax instruction parser mapping mnemonic and operands to iced-x86 Instruction.
 * Supports: NOP, RET, INT3, SYSCALL, LEAVE, JMP, CALL, Jcc, MOV, XOR, ADD, SUB, CMP, TEST, PUSH, POP, LEA.
 */
pub fn parse_intel_instruction(input: &str, target_va: u64) -> Result<Instruction> {
    let trimmed = input.trim();
    let (mnemonic, rest) = match trimmed.split_once(' ') {
        Some((m, r)) => (m.trim().to_ascii_lowercase(), r.trim()),
        None => (trimmed.to_ascii_lowercase(), ""),
    };

    match mnemonic.as_str() {
        /* nullary instructions */
        "nop" => Ok(Instruction::with(Code::Nopd)),
        "ret" | "retn" => Ok(Instruction::with(Code::Retnq)),
        "int3" => Ok(Instruction::with(Code::Int3)),
        "int" => {
            let imm = parse_number(rest)?;
            if imm == 3 {
                Ok(Instruction::with(Code::Int3))
            } else {
                Instruction::with1(Code::Int_imm8, imm as u32)
                    .map_err(|e| anyhow!("invalid int instruction: {}", e))
            }
        }
        "syscall" => Ok(Instruction::with(Code::Syscall)),
        "leave" => Ok(Instruction::with(Code::Leaveq)),

        /* control flow: CALL */
        "call" => {
            if let Ok(reg) = parse_register(rest) {
                Instruction::with1(Code::Call_rm64, reg)
                    .map_err(|e| anyhow!("invalid call register: {}", e))
            } else {
                let target = parse_address_or_displacement(rest, target_va)?;
                Instruction::with_branch(Code::Call_rel32_64, target)
                    .map_err(|e| anyhow!("invalid call branch target: {}", e))
            }
        }

        /* control flow: JMP */
        "jmp" => {
            if let Ok(reg) = parse_register(rest) {
                Instruction::with1(Code::Jmp_rm64, reg)
                    .map_err(|e| anyhow!("invalid jmp register: {}", e))
            } else {
                let target = parse_address_or_displacement(rest, target_va)?;
                Instruction::with_branch(Code::Jmp_rel32_64, target)
                    .map_err(|e| anyhow!("invalid jmp branch target: {}", e))
            }
        }

        /* conditional branches */
        "je" | "jz" => parse_branch_cond(Code::Je_rel32_64, rest, target_va),
        "jne" | "jnz" => parse_branch_cond(Code::Jne_rel32_64, rest, target_va),
        "ja" | "jnbe" => parse_branch_cond(Code::Ja_rel32_64, rest, target_va),
        "jae" | "jnb" | "jnc" => parse_branch_cond(Code::Jae_rel32_64, rest, target_va),
        "jb" | "jnae" | "jc" => parse_branch_cond(Code::Jb_rel32_64, rest, target_va),
        "jbe" | "jna" => parse_branch_cond(Code::Jbe_rel32_64, rest, target_va),
        "jg" | "jnle" => parse_branch_cond(Code::Jg_rel32_64, rest, target_va),
        "jge" | "jnl" => parse_branch_cond(Code::Jge_rel32_64, rest, target_va),
        "jl" | "jnge" => parse_branch_cond(Code::Jl_rel32_64, rest, target_va),
        "jle" | "jng" => parse_branch_cond(Code::Jle_rel32_64, rest, target_va),
        "js" => parse_branch_cond(Code::Js_rel32_64, rest, target_va),
        "jns" => parse_branch_cond(Code::Jns_rel32_64, rest, target_va),

        /* stack manipulation: PUSH / POP */
        "push" => {
            if let Ok(reg) = parse_register(rest) {
                Instruction::with1(Code::Push_r64, reg)
                    .map_err(|e| anyhow!("invalid push register: {}", e))
            } else {
                let imm = parse_number(rest)?;
                Instruction::with1(Code::Pushd_imm32, imm as i32)
                    .map_err(|e| anyhow!("invalid push immediate: {}", e))
            }
        }
        "pop" => {
            let reg = parse_register(rest)?;
            Instruction::with1(Code::Pop_r64, reg)
                .map_err(|e| anyhow!("invalid pop register: {}", e))
        }

        /* arithmetic and logical two-operand instructions */
        "xor" => parse_two_operand_alu(Code::Xor_rm64_r64, Code::Xor_rm32_r32, Code::Xor_rm64_imm32, rest),
        "add" => parse_two_operand_alu(Code::Add_rm64_r64, Code::Add_rm32_r32, Code::Add_rm64_imm32, rest),
        "sub" => parse_two_operand_alu(Code::Sub_rm64_r64, Code::Sub_rm32_r32, Code::Sub_rm64_imm32, rest),
        "cmp" => parse_two_operand_alu(Code::Cmp_rm64_r64, Code::Cmp_rm32_r32, Code::Cmp_rm64_imm32, rest),
        "test" => parse_two_operand_alu(Code::Test_rm64_r64, Code::Test_rm32_r32, Code::Test_rm64_imm32, rest),

        /* data movement: MOV */
        "mov" => parse_mov_instruction(rest),

        /* address calculation: LEA */
        "lea" => parse_lea_instruction(rest),

        _ => Err(anyhow!("unsupported or unrecognized instruction mnemonic: '{}'", mnemonic)),
    }
}

/* parse conditional branch helper */
fn parse_branch_cond(code: Code, rest: &str, current_va: u64) -> Result<Instruction> {
    let target = parse_address_or_displacement(rest, current_va)?;
    Instruction::with_branch(code, target).map_err(|e| anyhow!("failed to construct branch: {}", e))
}

/* parse target address from direct hex/decimal or relative offset */
fn parse_address_or_displacement(input: &str, current_va: u64) -> Result<u64> {
    let s = input.trim();
    if let Some(pos) = s.strip_prefix('+') {
        let disp = parse_number(pos)?;
        Ok(current_va.wrapping_add(disp))
    } else if let Some(neg) = s.strip_prefix('-') {
        let disp = parse_number(neg)?;
        Ok(current_va.wrapping_sub(disp))
    } else {
        parse_number(s)
    }
}

/* parse two-operand ALU instruction (e.g. XOR rax, rax or ADD rdi, 4) */
fn parse_two_operand_alu(code_r64: Code, code_r32: Code, code_imm: Code, rest: &str) -> Result<Instruction> {
    let (op1, op2) = rest.split_once(',')
        .ok_or_else(|| anyhow!("expected two comma-separated operands"))?;
    let op1 = op1.trim();
    let op2 = op2.trim();

    let reg1 = parse_register(op1)?;
    if let Ok(reg2) = parse_register(op2) {
        if is_64bit_reg(reg1) {
            Instruction::with2(code_r64, reg1, reg2)
                .map_err(|e| anyhow!("failed to create 64-bit alu instruction: {}", e))
        } else {
            Instruction::with2(code_r32, reg1, reg2)
                .map_err(|e| anyhow!("failed to create 32-bit alu instruction: {}", e))
        }
    } else {
        let imm = parse_number(op2)?;
        Instruction::with2(code_imm, reg1, imm as i32)
            .map_err(|e| anyhow!("failed to create immediate alu instruction: {}", e))
    }
}

/* parse MOV instruction supporting reg-reg, reg-imm, reg-mem, and mem-reg */
fn parse_mov_instruction(rest: &str) -> Result<Instruction> {
    let (op1, op2) = rest.split_once(',')
        .ok_or_else(|| anyhow!("MOV instruction requires two comma-separated operands"))?;
    let op1 = op1.trim();
    let op2 = op2.trim();

    /* destination is memory */
    if op1.starts_with('[') && op1.ends_with(']') {
        let mem = parse_memory_operand(op1)?;
        let src_reg = parse_register(op2)?;
        if is_64bit_reg(src_reg) {
            return Instruction::with2(Code::Mov_rm64_r64, mem, src_reg)
                .map_err(|e| anyhow!("failed to build mov [mem], reg: {}", e));
        } else {
            return Instruction::with2(Code::Mov_rm32_r32, mem, src_reg)
                .map_err(|e| anyhow!("failed to build mov [mem], reg: {}", e));
        }
    }

    /* source is memory */
    if op2.starts_with('[') && op2.ends_with(']') {
        let dst_reg = parse_register(op1)?;
        let mem = parse_memory_operand(op2)?;
        if is_64bit_reg(dst_reg) {
            return Instruction::with2(Code::Mov_r64_rm64, dst_reg, mem)
                .map_err(|e| anyhow!("failed to build mov reg, [mem]: {}", e));
        } else {
            return Instruction::with2(Code::Mov_r32_rm32, dst_reg, mem)
                .map_err(|e| anyhow!("failed to build mov reg, [mem]: {}", e));
        }
    }

    /* register destination */
    let dst_reg = parse_register(op1)?;
    if let Ok(src_reg) = parse_register(op2) {
        if is_64bit_reg(dst_reg) {
            Instruction::with2(Code::Mov_rm64_r64, dst_reg, src_reg)
                .map_err(|e| anyhow!("failed to build mov reg, reg: {}", e))
        } else {
            Instruction::with2(Code::Mov_rm32_r32, dst_reg, src_reg)
                .map_err(|e| anyhow!("failed to build mov reg, reg: {}", e))
        }
    } else {
        let imm = parse_number(op2)?;
        if is_64bit_reg(dst_reg) {
            Instruction::with2(Code::Mov_r64_imm64, dst_reg, imm)
                .map_err(|e| anyhow!("failed to build mov reg, imm64: {}", e))
        } else {
            Instruction::with2(Code::Mov_r32_imm32, dst_reg, imm as u32)
                .map_err(|e| anyhow!("failed to build mov reg, imm32: {}", e))
        }
    }
}

/* parse LEA instruction (e.g. LEA rax, [rip + 0x1000] or LEA rdi, [rbp - 8]) */
fn parse_lea_instruction(rest: &str) -> Result<Instruction> {
    let (op1, op2) = rest.split_once(',')
        .ok_or_else(|| anyhow!("LEA instruction requires destination and memory operands"))?;
    let dst_reg = parse_register(op1.trim())?;
    let mem = parse_memory_operand(op2.trim())?;
    Instruction::with2(Code::Lea_r64_m, dst_reg, mem)
        .map_err(|e| anyhow!("failed to build lea instruction: {}", e))
}

/* parse memory operand inside brackets (e.g. [rax], [rbp-8], [rip+0x200]) */
fn parse_memory_operand(mem_str: &str) -> Result<MemoryOperand> {
    let s = mem_str.trim();
    let inner = s.strip_prefix('[').and_then(|t| t.strip_suffix(']'))
        .ok_or_else(|| anyhow!("expected memory operand enclosed in brackets '[...]'"))?
        .trim();

    /* check for displacement: + or - */
    if let Some((base_s, disp_s)) = inner.split_once('+') {
        let base = parse_register(base_s.trim())?;
        let disp = parse_number(disp_s.trim())? as i64;
        Ok(MemoryOperand::new(base, Register::None, 1, disp, 4, false, Register::None))
    } else if let Some((base_s, disp_s)) = inner.split_once('-') {
        let base = parse_register(base_s.trim())?;
        let disp = parse_number(disp_s.trim())? as i64;
        Ok(MemoryOperand::new(base, Register::None, 1, -disp, 4, false, Register::None))
    } else {
        let base = parse_register(inner)?;
        Ok(MemoryOperand::new(base, Register::None, 1, 0, 0, false, Register::None))
    }
}

/* parse register token into iced-x86 Register enum */
pub fn parse_register(reg: &str) -> Result<Register> {
    let s = reg.trim().to_ascii_lowercase();
    match s.as_str() {
        /* 64-bit general purpose registers */
        "rax" => Ok(Register::RAX),
        "rcx" => Ok(Register::RCX),
        "rdx" => Ok(Register::RDX),
        "rbx" => Ok(Register::RBX),
        "rsp" => Ok(Register::RSP),
        "rbp" => Ok(Register::RBP),
        "rsi" => Ok(Register::RSI),
        "rdi" => Ok(Register::RDI),
        "r8" => Ok(Register::R8),
        "r9" => Ok(Register::R9),
        "r10" => Ok(Register::R10),
        "r11" => Ok(Register::R11),
        "r12" => Ok(Register::R12),
        "r13" => Ok(Register::R13),
        "r14" => Ok(Register::R14),
        "r15" => Ok(Register::R15),
        "rip" => Ok(Register::RIP),

        /* 32-bit registers */
        "eax" => Ok(Register::EAX),
        "ecx" => Ok(Register::ECX),
        "edx" => Ok(Register::EDX),
        "ebx" => Ok(Register::EBX),
        "esp" => Ok(Register::ESP),
        "ebp" => Ok(Register::EBP),
        "esi" => Ok(Register::ESI),
        "edi" => Ok(Register::EDI),
        "r8d" => Ok(Register::R8D),
        "r9d" => Ok(Register::R9D),
        "r10d" => Ok(Register::R10D),
        "r11d" => Ok(Register::R11D),
        "r12d" => Ok(Register::R12D),
        "r13d" => Ok(Register::R13D),
        "r14d" => Ok(Register::R14D),
        "r15d" => Ok(Register::R15D),

        /* 16-bit registers */
        "ax" => Ok(Register::AX),
        "cx" => Ok(Register::CX),
        "dx" => Ok(Register::DX),
        "bx" => Ok(Register::BX),
        "sp" => Ok(Register::SP),
        "bp" => Ok(Register::BP),
        "si" => Ok(Register::SI),
        "di" => Ok(Register::DI),

        /* 8-bit registers */
        "al" => Ok(Register::AL),
        "cl" => Ok(Register::CL),
        "dl" => Ok(Register::DL),
        "bl" => Ok(Register::BL),
        "spl" => Ok(Register::SPL),
        "bpl" => Ok(Register::BPL),
        "sil" => Ok(Register::SIL),
        "dil" => Ok(Register::DIL),

        _ => Err(anyhow!("unrecognized x86_64 register: '{}'", s)),
    }
}

/* check if a register is a 64-bit general purpose register */
fn is_64bit_reg(r: Register) -> bool {
    matches!(
        r,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::RBX
            | Register::RSP
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
            | Register::RIP
    )
}

/* parse a numeric literal in hex or decimal */
pub fn parse_number(num_str: &str) -> Result<u64> {
    let s = num_str.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|e| anyhow!("invalid hex value '{}': {}", s, e))
    } else if s.ends_with('h') || s.ends_with('H') {
        u64::from_str_radix(&s[..s.len() - 1], 16)
            .map_err(|e| anyhow!("invalid hex value '{}': {}", s, e))
    } else {
        s.parse::<u64>()
            .map_err(|e| anyhow!("invalid decimal value '{}': {}", s, e))
    }
}

/* parse space or comma separated hex bytes (e.g. '90 90 c3' or '0x90, 0x90') */
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for token in s.split(|c: char| c.is_whitespace() || c == ',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        let stripped = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        let byte = u8::from_str_radix(stripped, 16)
            .map_err(|e| anyhow!("invalid hex byte '{}': {}", t, e))?;
        bytes.push(byte);
    }
    if bytes.is_empty() {
        return Err(anyhow!("no valid hex bytes provided"));
    }
    Ok(bytes)
}
