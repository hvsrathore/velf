/* unit tests for x86_64 instruction parsing, block encoding, and in-place safety */

use velf::arch::{
    disassemble_slice, parse_and_encode_instruction, parse_intel_instruction,
};

#[test]
fn test_instruction_decoding_and_formatting() {
    /* byte stream: NOP (0x90), RET (0xc3), XOR EAX, EAX (0x31 0xc0) */
    let bytes = [0x90, 0xc3, 0x31, 0xc0];
    let instrs = disassemble_slice(&bytes, 0x401000, 0x1000);

    assert_eq!(instrs.len(), 3);
    assert_eq!(instrs[0].mnemonic, "nop");
    assert_eq!(instrs[1].mnemonic, "ret");
    assert_eq!(instrs[2].mnemonic, "xor");
    assert_eq!(instrs[2].op_str, "eax,eax");
}

#[test]
fn test_intel_syntax_parser() {
    /* test nullary instructions */
    assert!(parse_intel_instruction("nop", 0x401000).is_ok());
    assert!(parse_intel_instruction("ret", 0x401000).is_ok());
    assert!(parse_intel_instruction("int3", 0x401000).is_ok());

    /* test branches */
    assert!(parse_intel_instruction("jmp 0x401050", 0x401000).is_ok());
    assert!(parse_intel_instruction("call 0x401050", 0x401000).is_ok());
    assert!(parse_intel_instruction("je 0x401020", 0x401000).is_ok());
    assert!(parse_intel_instruction("jne 0x401020", 0x401000).is_ok());

    /* test alu operations */
    assert!(parse_intel_instruction("xor eax, eax", 0x401000).is_ok());
    assert!(parse_intel_instruction("add rax, rcx", 0x401000).is_ok());
    assert!(parse_intel_instruction("sub rsp, 0x28", 0x401000).is_ok());
    assert!(parse_intel_instruction("cmp rax, 0", 0x401000).is_ok());
    assert!(parse_intel_instruction("mov rax, rbx", 0x401000).is_ok());
}

#[test]
fn test_inplace_binary_safety_nop_padding() {
    /*
     * original instruction was 5 bytes (e.g. CALL rel32).
     * Replacing with 1-byte NOP should succeed and pad leftover 4 bytes with 0x90.
     */
    let result = parse_and_encode_instruction("nop", 0x401000, 5);
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes.len(), 5);
    assert_eq!(bytes, vec![0x90, 0x90, 0x90, 0x90, 0x90]);
}

#[test]
fn test_inplace_binary_safety_rejection() {
    /*
     * original instruction was 1 byte (e.g. NOP).
     * Trying to fit 5-byte JMP rel32 into a 1-byte slot must be aborted with error.
     */
    let result = parse_and_encode_instruction("jmp 0x402000", 0x401000, 1);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("patch rejected"));
    assert!(err_msg.contains("exceeds original instruction size"));
}
