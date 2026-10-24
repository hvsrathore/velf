/* unit tests for JumpStack and UndoStack */

use velf::vim::{JumpStack, UndoStack};

#[test]
fn test_jump_stack_navigation() {
    let mut js = JumpStack::new();

    /* push locations */
    js.push(0x100, 0x401000);
    js.push(0x200, 0x402000);
    js.push(0x300, 0x403000);

    /* pop backward (Ctrl-o) */
    let (off, va) = js.pop_back((0x400, 0x404000)).unwrap();
    assert_eq!(off, 0x300);
    assert_eq!(va, 0x403000);

    let (off2, va2) = js.pop_back((0x300, 0x403000)).unwrap();
    assert_eq!(off2, 0x200);
    assert_eq!(va2, 0x402000);

    /* navigate forward (Ctrl-i) */
    let (off_fwd, va_fwd) = js.pop_forward((0x200, 0x402000)).unwrap();
    assert_eq!(off_fwd, 0x300);
    assert_eq!(va_fwd, 0x403000);
}

#[test]
fn test_undo_and_redo_stack() {
    /* construct minimal mock buffer */
    let mut bytes = vec![0x90, 0x90, 0x90, 0x90];
    let mut undo_stack = UndoStack::new();

    /* record patch */
    let old_bytes = vec![0x90, 0x90];
    let new_bytes = vec![0xcc, 0xcc];
    bytes[0..2].copy_from_slice(&new_bytes);
    undo_stack.push_single(0, old_bytes.clone(), new_bytes.clone());

    assert_eq!(&bytes[0..2], &[0xcc, 0xcc]);

    /* undo */
    let p = undo_stack.undo_records.pop().unwrap();
    match p {
        velf::vim::PatchRecord::Single(s) => {
            bytes[s.file_offset..s.file_offset + s.old_bytes.len()].copy_from_slice(&s.old_bytes);
            undo_stack.redo_records.push(velf::vim::PatchRecord::Single(s));
        }
        _ => panic!("expected single patch"),
    }
    assert_eq!(&bytes[0..2], &[0x90, 0x90]);

    /* redo */
    let r = undo_stack.redo_records.pop().unwrap();
    match r {
        velf::vim::PatchRecord::Single(s) => {
            bytes[s.file_offset..s.file_offset + s.new_bytes.len()].copy_from_slice(&s.new_bytes);
        }
        _ => panic!("expected single patch"),
    }
    assert_eq!(&bytes[0..2], &[0xcc, 0xcc]);
}
