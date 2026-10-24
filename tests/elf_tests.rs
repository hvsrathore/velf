/* unit tests for ELF parsing, field descriptor table, and address translation */

use velf::elf::{parse_field_input, ElfBinary};

#[test]
fn test_field_input_parsing() {
    /* hex & decimal */
    assert_eq!(parse_field_input("0x401000", false, "e_entry").unwrap(), 0x401000);
    assert_eq!(parse_field_input("4096", false, "p_align").unwrap(), 4096);

    /* segment flags */
    let p_flags = parse_field_input("PF_R | PF_X", true, "p_flags").unwrap();
    assert_eq!(p_flags, 4 | 1); /* PF_R = 4, PF_X = 1 */

    let p_flags_rwx = parse_field_input("rwx", true, "p_flags").unwrap();
    assert_eq!(p_flags_rwx, 4 | 2 | 1);

    /* section flags */
    let sh_flags = parse_field_input("SHF_ALLOC | SHF_EXECINSTR", true, "sh_flags").unwrap();
    assert_eq!(sh_flags, 2 | 4);

    let sh_flags_wax = parse_field_input("wax", true, "sh_flags").unwrap();
    assert_eq!(sh_flags_wax, 1 | 2 | 4);
}

#[test]
fn test_elf_binary_parsing_on_self() {
    /* test loading and parsing an existing ELF executable (/proc/self/exe) */
    let self_path = std::fs::canonicalize("/proc/self/exe").unwrap();
    let elf = ElfBinary::load_from_file(&self_path).unwrap();

    assert!(elf.is_64);
    assert!(!elf.sections.is_empty());
    assert!(!elf.segments.is_empty());
    assert!(!elf.fields.is_empty());

    /* verify entry point translation */
    let entry_va = elf.entry;
    if let Some(off) = elf.va_to_offset(entry_va) {
        let back_va = elf.offset_to_va(off).unwrap();
        assert_eq!(back_va, entry_va);
    }
}
