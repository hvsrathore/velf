/* string literal scanner, inspector table, and in-place null-terminated editor */

use crate::elf::ElfBinary;
use crate::xref::XrefMap;
use anyhow::{anyhow, Result};

/* extracted string entry with physical file bounds and incoming cross references */
#[derive(Debug, Clone)]
pub struct StringEntry {
    pub file_offset: usize,
    pub va: u64,
    pub max_slot_len: usize, /* total available space including trailing 0x00 bytes */
    pub section_name: String,
    pub content: String,
    pub xref_count: usize,
}

/* scan ELF binary sections for printable null-terminated string sequences */
pub fn scan_strings(elf: &ElfBinary, xrefs: &XrefMap) -> Vec<StringEntry> {
    let mut entries = Vec::new();

    for sec in &elf.sections {
        /*
         * scan .rodata, .data, .dynstr, .strtab, and sections marked with SHF_STRINGS (0x20).
         * These sections store string tables, format strings, and constant text literals.
         */
        let is_target_sec = sec.name == ".rodata"
            || sec.name == ".data"
            || sec.name == ".dynstr"
            || sec.name == ".strtab"
            || (sec.sh_flags & 0x20) != 0;

        if !is_target_sec || sec.sh_size == 0 {
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
            /* find beginning of printable ASCII sequence */
            if is_printable_ascii(sec_bytes[idx]) {
                let str_start = idx;
                while idx < sec_bytes.len() && is_printable_ascii(sec_bytes[idx]) {
                    idx += 1;
                }

                let str_len = idx - str_start;

                /* require minimum length of 4 characters */
                if str_len >= 4 {
                    /* measure trailing null bytes (0x00) to determine slot capacity */
                    let mut slot_end = idx;
                    while slot_end < sec_bytes.len() && sec_bytes[slot_end] == 0x00 {
                        slot_end += 1;
                    }

                    let raw_slice = &sec_bytes[str_start..idx];
                    if let Ok(utf8_str) = std::str::from_utf8(raw_slice) {
                        let file_offset = start_off + str_start;
                        let va = if sec.sh_addr > 0 {
                            sec.sh_addr + str_start as u64
                        } else {
                            elf.offset_to_va(file_offset).unwrap_or(0)
                        };

                        let max_slot_len = slot_end - str_start;
                        let xref_count = xrefs.xref_count(va);

                        entries.push(StringEntry {
                            file_offset,
                            va,
                            max_slot_len,
                            section_name: sec.name.clone(),
                            content: utf8_str.to_string(),
                            xref_count,
                        });
                    }

                    idx = slot_end;
                    continue;
                }
            }
            idx += 1;
        }
    }

    entries
}

/* check if a byte falls within printable ASCII character range */
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

/* escape control characters for inline editor rendering */
pub fn escape_string(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\0' => out.push_str("\\0"),
            _ => out.push(c),
        }
    }
    out
}

/* parse escaped string input into raw machine bytes */
pub fn unescape_string(input: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => bytes.push(b'\n'),
                Some('r') => bytes.push(b'\r'),
                Some('t') => bytes.push(b'\t'),
                Some('\\') => bytes.push(b'\\'),
                Some('"') => bytes.push(b'"'),
                Some('0') => bytes.push(0x00),
                Some('x') => {
                    /* hexadecimal escape: \xHH */
                    let h1 = chars.next().ok_or_else(|| anyhow!("incomplete hex escape \\x"))?;
                    let h2 = chars.next().ok_or_else(|| anyhow!("incomplete hex escape \\x"))?;
                    let hex_str = format!("{}{}", h1, h2);
                    let byte = u8::from_str_radix(&hex_str, 16)
                        .map_err(|e| anyhow!("invalid hex escape '\\x{}': {}", hex_str, e))?;
                    bytes.push(byte);
                }
                Some(other) => {
                    bytes.push(b'\\');
                    let mut buf = [0u8; 4];
                    bytes.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => bytes.push(b'\\'),
            }
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    Ok(bytes)
}

/*
 * validate and prepare an edited string payload with in-place null-termination safety.
 *
 * If new_bytes.len() + 1 exceeds max_slot_len, the edit is aborted to guarantee that
 * subsequent string offsets in .dynstr, .strtab, and .rodata are never displaced.
 * Otherwise, the slot is filled with the new bytes, a terminating 0x00 byte, and zero-padding.
 */
pub fn prepare_string_patch(input: &str, max_slot_len: usize) -> Result<Vec<u8>> {
    let raw_bytes = unescape_string(input)?;
    let required_len = raw_bytes.len() + 1; /* payload plus null terminator */

    if required_len > max_slot_len {
        return Err(anyhow!(
            "string edit rejected: byte length ({} + 1 null = {} bytes) exceeds original slot capacity ({} bytes)",
            raw_bytes.len(),
            required_len,
            max_slot_len
        ));
    }

    let mut slot = raw_bytes;
    slot.push(0x00); /* null terminator */
    slot.resize(max_slot_len, 0x00); /* zero-fill leftover capacity */
    Ok(slot)
}
