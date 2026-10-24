/* global fuzzy symbol search index and modal provider */

use crate::elf::ElfBinary;

/* unified symbol representation for interactive search */
#[derive(Debug, Clone)]
pub struct UnifiedSymbol {
    pub name: String,
    pub sym_type: String,
    pub binding: String,
    pub va: u64,
    pub file_offset: usize,
    pub size: u64,
    pub section_name: String,
    pub is_plt: bool,
}

/* searchable index containing all static, dynamic, and PLT symbols */
#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    pub symbols: Vec<UnifiedSymbol>,
}

impl SymbolIndex {
    /* aggregate all symbols from .symtab, .dynsym, and PLT trampolines */
    pub fn build(elf: &ElfBinary) -> Self {
        let mut symbols = Vec::new();

        /* 1. Add static and dynamic symbols from ElfBinary */
        for sym in &elf.symbols {
            if sym.name.is_empty() {
                continue;
            }

            let sym_type = if sym.is_function {
                "STT_FUNC".to_string()
            } else if sym.is_object {
                "STT_OBJECT".to_string()
            } else {
                "STT_OTHER".to_string()
            };

            let binding = match sym.st_info >> 4 {
                0 => "LOCAL".to_string(),
                1 => "GLOBAL".to_string(),
                2 => "WEAK".to_string(),
                _ => "OTHER".to_string(),
            };

            let file_offset = elf.va_to_offset(sym.st_value).unwrap_or(0);
            let sec_name = if sym.st_shndx < elf.sections.len() {
                elf.sections[sym.st_shndx].name.clone()
            } else {
                "*ABS*".to_string()
            };

            symbols.push(UnifiedSymbol {
                name: sym.name.clone(),
                sym_type,
                binding,
                va: sym.st_value,
                file_offset,
                size: sym.st_size,
                section_name: sec_name,
                is_plt: false,
            });
        }

        /* 2. Add PLT/GOT relocation symbols */
        for reloc in &elf.relocations {
            if let Some(ref name) = reloc.sym_name {
                let plt_name = format!("{}@plt", name);
                if !symbols.iter().any(|s| s.name == plt_name) {
                    let file_offset = elf.va_to_offset(reloc.r_offset).unwrap_or(0);
                    symbols.push(UnifiedSymbol {
                        name: plt_name,
                        sym_type: "STT_FUNC (PLT)".to_string(),
                        binding: "GLOBAL".to_string(),
                        va: reloc.r_offset,
                        file_offset,
                        size: 16,
                        section_name: ".plt".to_string(),
                        is_plt: true,
                    });
                }
            }
        }

        Self { symbols }
    }

    /* filter symbols by real-time query using fuzzy substring scoring */
    pub fn search(&self, query: &str) -> Vec<&UnifiedSymbol> {
        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return self.symbols.iter().collect();
        }

        let mut scored: Vec<(&UnifiedSymbol, i32)> = self
            .symbols
            .iter()
            .filter_map(|s| {
                let score = fuzzy_score(&s.name, &q)?;
                Some((s, score))
            })
            .collect();

        /* sort by highest match score */
        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored.into_iter().map(|(s, _)| s).collect()
    }
}

/*
 * calculate fuzzy matching score between a target string and a query pattern.
 * Rewards exact matches, prefix matches, and consecutive character sequences.
 */
fn fuzzy_score(target: &str, query: &str) -> Option<i32> {
    let lower_target = target.to_ascii_lowercase();
    if let Some(idx) = lower_target.find(query) {
        /* exact substring match bonus */
        let mut score = 1000 - (idx as i32 * 10);
        if idx == 0 {
            score += 500; /* prefix bonus */
        }
        return Some(score);
    }

    /* sequential fuzzy character scan */
    let mut score = 0;
    let mut target_chars = lower_target.chars().enumerate();
    let mut last_match_idx = None;

    for qc in query.chars() {
        let mut found = false;
        while let Some((idx, tc)) = target_chars.next() {
            if tc == qc {
                found = true;
                score += 10;
                if let Some(prev) = last_match_idx {
                    if idx == prev + 1 {
                        score += 30; /* consecutive match bonus */
                    }
                }
                last_match_idx = Some(idx);
                break;
            }
        }
        if !found {
            return None;
        }
    }

    Some(score)
}
