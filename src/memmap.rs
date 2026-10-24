/* visual memory layout, PT_LOAD segment timeline, and padding gap analyzer */

use crate::elf::{format_p_flags, ElfBinary, SectionInfo};

/* item type in the visual memory map timeline */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapItemKind {
    FileHeader,
    Segment(usize),
    Section(usize),
    PaddingGap,
}

/* an element positioned along the memory and physical file timeline */
#[derive(Debug, Clone)]
pub struct MapItem {
    pub kind: MapItemKind,
    pub name: String,
    pub file_offset: usize,
    pub file_size: usize,
    pub va_start: u64,
    pub va_size: u64,
    pub permissions: String,
    pub entropy: f64,
    pub translation_formula: String,
    pub segment_index: Option<usize>,
    pub section_index: Option<usize>,
}

/* unified memory map timeline container */
#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub items: Vec<MapItem>,
    pub max_va: u64,
    pub total_file_size: usize,
}

impl MemoryMap {
    /*
     * construct a unified timeline from file offset 0 to the maximum Virtual Address (VA).
     * Maps each PT_LOAD segment, contained sections, unmapped file headers,
     * and explicit inter-section alignment gaps.
     */
    pub fn build(elf: &ElfBinary) -> Self {
        let mut items = Vec::new();
        let total_file_size = elf.bytes.len();

        /* 1. Add ELF file header item (first 64 bytes) */
        let ehdr_len = if elf.is_64 { 64 } else { 52 }.min(total_file_size);
        let ehdr_entropy = calculate_entropy(&elf.bytes[0..ehdr_len]);
        items.push(MapItem {
            kind: MapItemKind::FileHeader,
            name: "ELF Header (Ehdr)".to_string(),
            file_offset: 0,
            file_size: ehdr_len,
            va_start: 0,
            va_size: 0,
            permissions: "r--".to_string(),
            entropy: ehdr_entropy,
            translation_formula: "unmapped in process virtual memory".to_string(),
            segment_index: None,
            section_index: None,
        });

        let mut max_va = 0u64;

        /* 2. Traverse each PT_LOAD segment */
        for seg in &elf.segments {
            if !seg.is_loadable {
                continue;
            }

            let seg_end_va = seg.p_vaddr + seg.p_memsz;
            if seg_end_va > max_va {
                max_va = seg_end_va;
            }

            let seg_bytes = get_slice(&elf.bytes, seg.p_offset as usize, seg.p_filesz as usize);
            let seg_entropy = calculate_entropy(seg_bytes);
            let perms = format_p_flags(seg.p_flags);

            let formula = format!(
                "file_offset = 0x{:x} + (va - 0x{:x})",
                seg.p_offset, seg.p_vaddr
            );

            items.push(MapItem {
                kind: MapItemKind::Segment(seg.index),
                name: format!("PT_LOAD[{}] (0x{:08x}-0x{:08x})", seg.index, seg.p_vaddr, seg_end_va),
                file_offset: seg.p_offset as usize,
                file_size: seg.p_filesz as usize,
                va_start: seg.p_vaddr,
                va_size: seg.p_memsz,
                permissions: perms,
                entropy: seg_entropy,
                translation_formula: formula,
                segment_index: Some(seg.index),
                section_index: None,
            });

            /* locate all sections contained within this PT_LOAD segment */
            let mut contained_sections: Vec<&SectionInfo> = elf
                .sections
                .iter()
                .filter(|s| {
                    s.sh_addr >= seg.p_vaddr
                        && (s.sh_addr + s.sh_size) <= (seg.p_vaddr + seg.p_memsz)
                        && s.sh_size > 0
                })
                .collect();

            contained_sections.sort_by_key(|s| s.sh_addr);

            /* track gaps between adjacent sections */
            let mut cur_va = seg.p_vaddr;
            let mut cur_off = seg.p_offset as usize;

            for sec in contained_sections {
                /* check for padding gap preceding section */
                if sec.sh_addr > cur_va {
                    let gap_va_len = sec.sh_addr - cur_va;
                    let gap_file_len = (sec.sh_offset as usize).saturating_sub(cur_off);
                    let gap_bytes = get_slice(&elf.bytes, cur_off, gap_file_len);
                    let gap_entropy = calculate_entropy(gap_bytes);

                    items.push(MapItem {
                        kind: MapItemKind::PaddingGap,
                        name: format!("Alignment Padding ({} bytes)", gap_file_len),
                        file_offset: cur_off,
                        file_size: gap_file_len,
                        va_start: cur_va,
                        va_size: gap_va_len,
                        permissions: "---".to_string(),
                        entropy: gap_entropy,
                        translation_formula: format!(
                            "alignment hole between sections (0x{:x}..0x{:x})",
                            cur_va, sec.sh_addr
                        ),
                        segment_index: Some(seg.index),
                        section_index: None,
                    });
                }

                /* add section sub-block */
                let sec_bytes = get_slice(&elf.bytes, sec.sh_offset as usize, sec.sh_size as usize);
                let sec_entropy = calculate_entropy(sec_bytes);
                let sec_formula = format!(
                    "file_offset = 0x{:x} + (va - 0x{:x})",
                    sec.sh_offset, sec.sh_addr
                );

                items.push(MapItem {
                    kind: MapItemKind::Section(sec.index),
                    name: format!("  └─ {} (idx {})", sec.name, sec.index),
                    file_offset: sec.sh_offset as usize,
                    file_size: sec.sh_size as usize,
                    va_start: sec.sh_addr,
                    va_size: sec.sh_size,
                    permissions: if sec.is_executable { "r-x" } else { "rw-" }.to_string(),
                    entropy: sec_entropy,
                    translation_formula: sec_formula,
                    segment_index: Some(seg.index),
                    section_index: Some(sec.index),
                });

                cur_va = sec.sh_addr + sec.sh_size;
                cur_off = (sec.sh_offset + sec.sh_size) as usize;
            }
        }

        Self {
            items,
            max_va,
            total_file_size,
        }
    }
}

/* slice helper preventing out-of-bounds panics */
fn get_slice(bytes: &[u8], start: usize, len: usize) -> &[u8] {
    if start >= bytes.len() {
        &[]
    } else {
        let end = (start + len).min(bytes.len());
        &bytes[start..end]
    }
}

/*
 * calculate Shannon entropy of a byte slice:
 * H(X) = - sum(p(x) * log2(p(x)))
 * Ranges from 0.0 (all identical bytes, e.g. NOP sleds or null zero-fill)
 * to 8.0 (completely random, encrypted, or compressed data).
 */
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}
