/* automated ELF security hardening audit scanner */

use crate::elf::ElfBinary;
use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK};

/* hardening mitigation evaluation status */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitigationStatus {
    Hardened, /* green badge */
    Partial,  /* yellow badge */
    Missing,  /* red badge */
}

/* single security mitigation report */
#[derive(Debug, Clone)]
pub struct AuditItem {
    pub name: String,
    pub status: MitigationStatus,
    pub description: String,
    pub remediation: String,
    pub target_field_name: Option<String>,
    pub target_file_offset: Option<usize>,
}

/* comprehensive security posture report */
#[derive(Debug, Clone)]
pub struct SecurityReport {
    pub items: Vec<AuditItem>,
}

impl SecurityReport {
    /* evaluate key binary mitigations: RELRO, NX Stack, Stack Canaries, and PIE */
    pub fn scan(elf: &ElfBinary) -> Self {
        let mut items = Vec::new();

        /*
         * (a) RELRO (Relocation Read-Only) audit:
         * Full RELRO: PT_GNU_RELRO exists and BIND_NOW is set.
         * Partial RELRO: PT_GNU_RELRO exists without BIND_NOW (.got is read-only after init, but .got.plt remains writable).
         * No RELRO: No PT_GNU_RELRO segment.
         */
        let relro_segment = elf.segments.iter().find(|s| s.p_type == PT_GNU_RELRO);
        let has_relro = relro_segment.is_some();

        /* check goblin dynamic section for DT_BIND_NOW or DF_BIND_NOW */
        let mut has_bind_now = false;
        if let Ok(parsed_elf) = goblin::elf::Elf::parse(&elf.bytes) {
            if let Some(dyn_sec) = parsed_elf.dynamic {
                for d in dyn_sec.dyns {
                    if d.d_tag == 24 {
                        /* DT_BIND_NOW */
                        has_bind_now = true;
                    } else if d.d_tag == 30 && (d.d_val & 0x8) != 0 {
                        /* DT_FLAGS & DF_BIND_NOW */
                        has_bind_now = true;
                    } else if d.d_tag == 0x6ffffffb && (d.d_val & 0x1) != 0 {
                        /* DT_FLAGS_1 & DF_1_NOW */
                        has_bind_now = true;
                    }
                }
            }
        }

        let (relro_status, relro_desc, relro_remediation) = match (has_relro, has_bind_now) {
            (true, true) => (
                MitigationStatus::Hardened,
                "Full RELRO: PT_GNU_RELRO present and BIND_NOW set; GOT and PLT are read-only post-load.".to_string(),
                "Hardened: GOT overwrite attacks prevented.".to_string(),
            ),
            (true, false) => (
                MitigationStatus::Partial,
                "Partial RELRO: PT_GNU_RELRO present but lazy binding enabled; .got.plt is writable.".to_string(),
                "Remediation: re-link with -Wl,-z,relro,-z,now to achieve Full RELRO.".to_string(),
            ),
            (false, _) => (
                MitigationStatus::Missing,
                "No RELRO: no PT_GNU_RELRO program header; GOT and PLT tables are fully writable.".to_string(),
                "Remediation: re-link with -Wl,-z,relro,-z,now.".to_string(),
            ),
        };

        items.push(AuditItem {
            name: "RELRO (Relocation Read-Only)".to_string(),
            status: relro_status,
            description: relro_desc,
            remediation: relro_remediation,
            target_field_name: Some("p_type".to_string()),
            target_file_offset: relro_segment.map(|s| s.p_offset as usize),
        });

        /*
         * (b) NX Bit / Non-Executable Stack:
         * Checks the PT_GNU_STACK program header.
         * If p_flags does not have PF_X (0x1), stack memory is non-executable (NX enabled).
         * If PF_X is set, the kernel maps the stack as executable (stack buffer execution vulnerability).
         */
        let stack_segment = elf.segments.iter().find(|s| s.p_type == PT_GNU_STACK);
        let (nx_status, nx_desc, nx_remediation) = match stack_segment {
            Some(seg) => {
                let is_exec = (seg.p_flags & PF_X) != 0;
                if !is_exec {
                    (
                        MitigationStatus::Hardened,
                        "NX Enabled: PT_GNU_STACK lacks PF_X; stack memory is non-executable.".to_string(),
                        "Hardened: prevents shellcode execution on the stack.".to_string(),
                    )
                } else {
                    (
                        MitigationStatus::Missing,
                        "NX Disabled: PT_GNU_STACK has PF_X set; stack is executable!".to_string(),
                        "Remediation: clear the PF_X flag or re-link with -Wl,-z,noexecstack.".to_string(),
                    )
                }
            }
            None => (
                MitigationStatus::Missing,
                "NX Missing: no PT_GNU_STACK header found; kernel may default to executable stack.".to_string(),
                "Remediation: add PT_GNU_STACK program header without PF_X.".to_string(),
            ),
        };

        let stack_field_offset = stack_segment.and_then(|s| {
            elf.fields
                .iter()
                .find(|f| f.file_offset == (s.p_offset as usize + 4))
                .map(|f| f.file_offset)
        });

        items.push(AuditItem {
            name: "NX Bit (Non-Executable Stack)".to_string(),
            status: nx_status,
            description: nx_desc,
            remediation: nx_remediation,
            target_field_name: Some("p_flags".to_string()),
            target_file_offset: stack_field_offset,
        });

        /*
         * (c) Stack Canaries:
         * Scans .symtab and .dynsym for __stack_chk_fail or __stack_chk_guard symbols
         * emitted by compiler stack smashing protectors (-fstack-protector).
         */
        let has_canary = elf.symbols.iter().any(|s| {
            s.name.contains("__stack_chk_fail") || s.name.contains("__stack_chk_guard")
        });

        let (canary_status, canary_desc, canary_remediation) = if has_canary {
            (
                MitigationStatus::Hardened,
                "Stack Canary Found: references to __stack_chk_fail detected in symbol tables.".to_string(),
                "Hardened: stack smashing protector active on vulnerable functions.".to_string(),
            )
        } else {
            (
                MitigationStatus::Missing,
                "No Stack Canaries: no __stack_chk_fail symbol found.".to_string(),
                "Remediation: recompile vulnerable modules with -fstack-protector-strong.".to_string(),
            )
        };

        items.push(AuditItem {
            name: "Stack Canaries".to_string(),
            status: canary_status,
            description: canary_desc,
            remediation: canary_remediation,
            target_field_name: None,
            target_file_offset: None,
        });

        /*
         * (d) PIE (Position-Independent Executable):
         * Checks Elf64_Ehdr e_type: ET_DYN indicates position-independent code loaded at ASLR random base.
         * ET_EXEC indicates a fixed virtual address binary vulnerable to fixed ROP gadget chaining.
         */
        let is_dyn = elf.header.e_type == ET_DYN;
        let (pie_status, pie_desc, pie_remediation) = if is_dyn {
            (
                MitigationStatus::Hardened,
                "PIE Enabled: object type is ET_DYN; binary supports full ASLR base address randomization.".to_string(),
                "Hardened: ASLR randomizes base Virtual Address on each execution.".to_string(),
            )
        } else {
            (
                MitigationStatus::Missing,
                "PIE Disabled: object type is ET_EXEC; binary loads at a fixed memory address.".to_string(),
                "Remediation: recompile with -fPIE and link with -pie.".to_string(),
            )
        };

        items.push(AuditItem {
            name: "PIE (Position-Independent Executable)".to_string(),
            status: pie_status,
            description: pie_desc,
            remediation: pie_remediation,
            target_field_name: Some("e_type".to_string()),
            target_file_offset: Some(16), /* e_type offset in Ehdr */
        });

        SecurityReport { items }
    }
}
