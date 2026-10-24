/* unit tests for string escaping, unescaping, and in-place null-termination safety */

use velf::strings::{escape_string, prepare_string_patch, unescape_string};

#[test]
fn test_string_escaping_and_unescaping() {
    let original = "Hello\nWorld\t\"Test\"\0";
    let escaped = escape_string(original);
    assert_eq!(escaped, r#"Hello\nWorld\t\"Test\"\0"#);

    let unescaped = unescape_string(&escaped).unwrap();
    assert_eq!(unescaped, original.as_bytes());
}

#[test]
fn test_hex_escapes() {
    let input = r#"Secret\x41\x42\x00"#;
    let bytes = unescape_string(input).unwrap();
    assert_eq!(bytes, b"SecretAB\x00");
}

#[test]
fn test_string_patch_safety_within_capacity() {
    /* slot capacity: 16 bytes. Payload "hello": 5 bytes + 1 null = 6 bytes */
    let res = prepare_string_patch("hello", 16);
    assert!(res.is_ok());
    let slot = res.unwrap();
    assert_eq!(slot.len(), 16);
    assert_eq!(&slot[0..6], b"hello\0");
    assert_eq!(&slot[6..], &[0u8; 10]); /* zero padding */
}

#[test]
fn test_string_patch_safety_overflow_rejection() {
    /* slot capacity: 8 bytes. Payload "longer_string": 13 bytes + 1 null = 14 bytes > 8 */
    let res = prepare_string_patch("longer_string", 8);
    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("string edit rejected"));
}
