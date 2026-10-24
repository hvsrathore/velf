/* vim modal state machine, jump stack, and undo/redo history engine */

use crate::elf::ElfBinary;
use anyhow::Result;

/* active modal state in the Vim finite state machine */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VimMode {
    Normal,
    FieldEdit,  /* structural header editing */
    AsmPatch,   /* inline x86_64 assembly patch */
    StringEdit, /* null-terminated string literal editing */
    HookEdit,   /* PLT/GOT relocation hook redirection */
    Command,    /* colon command-line prompt */
    Search,     /* forward slash substring filter prompt */
}

impl VimMode {
    pub fn badge_name(&self) -> &'static str {
        match self {
            VimMode::Normal => "-- NORMAL --",
            VimMode::FieldEdit => "-- FIELD EDIT --",
            VimMode::AsmPatch => "-- ASM PATCH --",
            VimMode::StringEdit => "-- STRING EDIT --",
            VimMode::HookEdit => "-- HOOK EDIT --",
            VimMode::Command => "-- COMMAND --",
            VimMode::Search => "-- SEARCH --",
        }
    }
}

/* jump stack maintaining LIFO history of file offsets and Virtual Addresses */
#[derive(Debug, Clone, Default)]
pub struct JumpStack {
    pub history: Vec<(usize, u64)>,
    pub future: Vec<(usize, u64)>,
}

impl JumpStack {
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            future: Vec::new(),
        }
    }

    /* push current cursor location onto jump stack */
    pub fn push(&mut self, file_offset: usize, va: u64) {
        /* avoid duplicate consecutive entries */
        if let Some(&(last_off, last_va)) = self.history.last() {
            if last_off == file_offset && last_va == va {
                return;
            }
        }
        self.history.push((file_offset, va));
        self.future.clear(); /* new branch invalidates forward redo history */
    }

    /* pop location backwards (Ctrl-o) */
    pub fn pop_back(&mut self, current_loc: (usize, u64)) -> Option<(usize, u64)> {
        let prev = self.history.pop()?;
        self.future.push(current_loc);
        Some(prev)
    }

    /* navigate forward along jump history tree (Ctrl-i) */
    pub fn pop_forward(&mut self, current_loc: (usize, u64)) -> Option<(usize, u64)> {
        let next = self.future.pop()?;
        self.history.push(current_loc);
        Some(next)
    }
}

/* single physical byte alteration */
#[derive(Debug, Clone)]
pub struct SinglePatch {
    pub file_offset: usize,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
}

/* atomic patch record supporting both single-site and composite trampoline edits */
#[derive(Debug, Clone)]
pub enum PatchRecord {
    Single(SinglePatch),
    Composite(Vec<SinglePatch>),
}

/* undo and redo history stack */
#[derive(Debug, Clone, Default)]
pub struct UndoStack {
    pub undo_records: Vec<PatchRecord>,
    pub redo_records: Vec<PatchRecord>,
}

impl UndoStack {
    pub fn new() -> Self {
        Self {
            undo_records: Vec::new(),
            redo_records: Vec::new(),
        }
    }

    /* record a single byte patch */
    pub fn push_single(&mut self, file_offset: usize, old_bytes: Vec<u8>, new_bytes: Vec<u8>) {
        self.undo_records.push(PatchRecord::Single(SinglePatch {
            file_offset,
            old_bytes,
            new_bytes,
        }));
        self.redo_records.clear();
    }

    /* record a composite multi-location trampoline patch */
    pub fn push_composite(&mut self, patches: Vec<SinglePatch>) {
        self.undo_records.push(PatchRecord::Composite(patches));
        self.redo_records.clear();
    }

    /*
     * undo most recent patch ('u').
     * Restores previous machine bytes in the ELF buffer and pushes to redo stack.
     */
    pub fn undo(&mut self, elf: &mut ElfBinary) -> Result<Option<usize>> {
        let record = match self.undo_records.pop() {
            Some(r) => r,
            None => return Ok(None),
        };

        let mut focus_offset = None;

        match &record {
            PatchRecord::Single(p) => {
                let end = p.file_offset + p.old_bytes.len();
                if end <= elf.bytes.len() {
                    elf.bytes[p.file_offset..end].copy_from_slice(&p.old_bytes);
                    focus_offset = Some(p.file_offset);
                }
            }
            PatchRecord::Composite(patches) => {
                for p in patches.iter().rev() {
                    let end = p.file_offset + p.old_bytes.len();
                    if end <= elf.bytes.len() {
                        elf.bytes[p.file_offset..end].copy_from_slice(&p.old_bytes);
                        focus_offset = Some(p.file_offset);
                    }
                }
            }
        }

        self.redo_records.push(record);
        let _ = elf.reparse();
        Ok(focus_offset)
    }

    /*
     * redo reverted patch ('Ctrl-r').
     * Re-applies newly patched machine code bytes.
     */
    pub fn redo(&mut self, elf: &mut ElfBinary) -> Result<Option<usize>> {
        let record = match self.redo_records.pop() {
            Some(r) => r,
            None => return Ok(None),
        };

        let mut focus_offset = None;

        match &record {
            PatchRecord::Single(p) => {
                let end = p.file_offset + p.new_bytes.len();
                if end <= elf.bytes.len() {
                    elf.bytes[p.file_offset..end].copy_from_slice(&p.new_bytes);
                    focus_offset = Some(p.file_offset);
                }
            }
            PatchRecord::Composite(patches) => {
                for p in patches {
                    let end = p.file_offset + p.new_bytes.len();
                    if end <= elf.bytes.len() {
                        elf.bytes[p.file_offset..end].copy_from_slice(&p.new_bytes);
                        focus_offset = Some(p.file_offset);
                    }
                }
            }
        }

        self.undo_records.push(record);
        let _ = elf.reparse();
        Ok(focus_offset)
    }
}
