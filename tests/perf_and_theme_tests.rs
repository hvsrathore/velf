/* unit and integration tests for instruction cache, viewport virtualization, theme engine, and parallel analysis */

use velf::arch::{InstructionCache, HEX_BYTE, HEX_TABLE};
use velf::entropy::EntropyAnalysis;
use velf::rop::scan_rop_gadgets_parallel;
use velf::theme::{Theme, ThemePreset};

#[test]
fn test_instruction_cache_lru_and_navigation() {
    /* byte sequence of three instructions:
     * 0x00: 90          (NOP)
     * 0x01: 90          (NOP)
     * 0x02: 31 c0       (XOR EAX, EAX)
     * 0x04: c3          (RET)
     */
    let bytes = [0x90, 0x90, 0x31, 0xc0, 0xc3];
    let mut cache = InstructionCache::new(512);

    /* pre-index range of instructions */
    cache.preindex_range(&bytes, 0, 0x401000, 10);

    /* verify all instruction offsets are indexed */
    assert_eq!(cache.known_offsets, vec![0, 1, 2, 4]);

    /* verify O(1) next_offset and prev_offset */
    assert_eq!(cache.next_offset(0), Some(1));
    assert_eq!(cache.next_offset(1), Some(2));
    assert_eq!(cache.next_offset(2), Some(4));
    assert_eq!(cache.next_offset(4), None);

    assert_eq!(cache.prev_offset(4), Some(2));
    assert_eq!(cache.prev_offset(2), Some(1));
    assert_eq!(cache.prev_offset(1), Some(0));
    assert_eq!(cache.prev_offset(0), None);

    /* verify cached instruction properties */
    let instr0 = cache.get(0).unwrap();
    assert_eq!(instr0.mnemonic, "nop");
    assert_eq!(instr0.len, 1);
    assert_eq!(instr0.formatted_hex, "90");

    let instr2 = cache.get(2).unwrap();
    assert_eq!(instr2.mnemonic, "xor");
    assert_eq!(instr2.len, 2);
    assert_eq!(instr2.formatted_hex, "31 c0");
}

#[test]
fn test_instruction_cache_lru_eviction() {
    let mut cache = InstructionCache::new(3);
    /* byte sequence of 4 NOPs */
    let bytes = [0x90, 0x90, 0x90, 0x90];

    cache.get_or_decode(&bytes, 0, 0x401000);
    cache.get_or_decode(&bytes, 1, 0x401001);
    cache.get_or_decode(&bytes, 2, 0x401002);

    /* access offset 0 so offset 1 becomes the least-recently used */
    let _ = cache.get(0);

    /* inserting 4th element should evict offset 1 */
    cache.get_or_decode(&bytes, 3, 0x401003);

    assert!(cache.get(0).is_some());
    assert!(cache.get(2).is_some());
    assert!(cache.get(3).is_some());
}

#[test]
fn test_hex_lookup_tables() {
    /* verify precomputed zero-allocation hex tables */
    assert_eq!(HEX_TABLE[0], "00 ");
    assert_eq!(HEX_TABLE[144], "90 "); /* NOP */
    assert_eq!(HEX_TABLE[195], "c3 "); /* RET */
    assert_eq!(HEX_TABLE[255], "ff ");

    assert_eq!(HEX_BYTE[0], "00");
    assert_eq!(HEX_BYTE[144], "90");
    assert_eq!(HEX_BYTE[195], "c3");
    assert_eq!(HEX_BYTE[255], "ff");
}

#[test]
fn test_theme_presets_and_cycling() {
    let nord = Theme::nord();
    assert_eq!(nord.preset, ThemePreset::Nord);

    let dracula = nord.cycle_next();
    assert_eq!(dracula.preset, ThemePreset::Dracula);

    let monokai = dracula.cycle_next();
    assert_eq!(monokai.preset, ThemePreset::Monokai);

    let gruvbox = monokai.cycle_next();
    assert_eq!(gruvbox.preset, ThemePreset::Gruvbox);

    let solarized = gruvbox.cycle_next();
    assert_eq!(solarized.preset, ThemePreset::Solarized);

    let back_to_nord = solarized.cycle_next();
    assert_eq!(back_to_nord.preset, ThemePreset::Nord);

    /* test lookup by name */
    assert_eq!(Theme::from_preset_name("Dracula").unwrap().preset, ThemePreset::Dracula);
    assert_eq!(Theme::from_preset_name("nord").unwrap().preset, ThemePreset::Nord);
    assert_eq!(Theme::from_preset_name("Gruvbox").unwrap().preset, ThemePreset::Gruvbox);
    assert!(Theme::from_preset_name("nonexistent").is_none());
}

#[test]
fn test_instruction_styled_spans_formatting() {
    let bytes = [0x48, 0x89, 0xd8, 0xc3]; /* MOV RAX, RBX ; RET */
    let mut cache = InstructionCache::new(512);
    let instr0 = cache.get_or_decode(&bytes, 0, 0x401000).unwrap();

    let theme = Theme::dracula();
    let spans = instr0.format_spans(&theme.palette, false);
    assert!(!spans.is_empty());

    /* check selection styling */
    let sel_spans = instr0.format_spans(&theme.palette, true);
    assert_eq!(sel_spans.len(), 2);
}

#[test]
fn test_parallel_entropy_calculation() {
    /* 512 bytes: first 256 zero bytes (entropy 0.0), next 256 random bytes */
    let mut data = vec![0u8; 256];
    for i in 0..256 {
        data.push(i as u8);
    }

    let analysis = EntropyAnalysis::compute_parallel(&data, Some(0x400000));
    assert_eq!(analysis.blocks.len(), 2);
    assert_eq!(analysis.blocks[0].entropy, 0.0);
    assert_eq!(analysis.blocks[1].entropy, 8.0);
    assert!(analysis.mean_entropy > 3.0 && analysis.mean_entropy < 5.0);
}

#[test]
fn test_parallel_rop_gadget_scanning_on_self() {
    let current_exe = std::env::current_exe().expect("current executable path");
    let elf = velf::elf::ElfBinary::load_from_file(&current_exe).expect("parse self ELF");

    let gadgets = scan_rop_gadgets_parallel(&elf);
    /* executable should contain numerous ROP gadgets */
    assert!(!gadgets.is_empty(), "expected ROP gadgets in compiled binary");

    /* all gadgets must have valid disassembly */
    for g in gadgets.iter().take(20) {
        assert!(g.va > 0);
        assert!(!g.instructions.is_empty());
        assert!(!g.disasm.is_empty());
    }
}
