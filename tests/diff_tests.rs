/* unit tests for sliding window binary hex diffing */

use velf::diff::compute_diff_chunks;

#[test]
fn test_identical_buffers_no_diff() {
    let buf1 = vec![0x90, 0x90, 0xc3, 0x00];
    let buf2 = vec![0x90, 0x90, 0xc3, 0x00];
    let chunks = compute_diff_chunks(&buf1, &buf2);
    assert!(chunks.is_empty());
}

#[test]
fn test_differing_bytes_chunking() {
    let buf1 = vec![0x90, 0x90, 0x11, 0x22, 0x90, 0x90, 0x90, 0x90, 0x90];
    let buf2 = vec![0x90, 0x90, 0xaa, 0xbb, 0x90, 0x90, 0x90, 0x90, 0x90];
    let chunks = compute_diff_chunks(&buf1, &buf2);

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].offset_a, 2);
    assert_eq!(chunks[0].length, 2);
    assert_eq!(chunks[0].bytes_a, vec![0x11, 0x22]);
    assert_eq!(chunks[0].bytes_b, vec![0xaa, 0xbb]);
}
