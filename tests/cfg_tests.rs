/* unit tests for control-flow graph (CFG) basic-block splitting */

use velf::arch::disassemble_slice;
use velf::cfg::ControlFlowGraph;
use velf::elf::SymbolInfo;

#[test]
fn test_cfg_basic_block_split() {
    /*
     * simulated function:
     * 0x401000: xor eax, eax
     * 0x401002: cmp eax, 0
     * 0x401005: je +0x5 (0x40100c)
     * 0x401007: mov eax, 1
     * 0x40100c: ret
     */
    let bytes = [
        0x31, 0xc0,             /* xor eax, eax */
        0x83, 0xf8, 0x00,       /* cmp eax, 0 */
        0x74, 0x05,             /* je +5 (0x40100e) */
        0xb8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1 */
        0xc3,                   /* ret */
    ];

    let instrs = disassemble_slice(&bytes, 0x401000, 0);
    let sym = SymbolInfo {
        name: "test_func".to_string(),
        st_value: 0x401000,
        st_size: bytes.len() as u64,
        st_info: 0x12,
        st_other: 0,
        st_shndx: 1,
        is_function: true,
        is_object: false,
        is_dynamic: false,
    };

    let cfg = ControlFlowGraph::build(&sym, &instrs).unwrap();
    assert!(cfg.graph.node_count() >= 2);
    assert!(!cfg.topo_order.is_empty());
}
