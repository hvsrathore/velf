/* inter-procedural function call-graph analysis and 2D hierarchical layout */

use crate::arch::disassemble_slice;
use crate::elf::ElfBinary;
use iced_x86::FlowControl;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet, VecDeque};

/* node in the global function call graph */
#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub id: usize,
    pub name: String,
    pub va: u64,
    pub size: u64,
    pub file_offset: usize,
    pub callers_count: usize,
    pub callees_count: usize,
    pub x: i32,
    pub y: i32,
    pub width: usize,
    pub height: usize,
    pub layer: usize,
}

/* directed caller-to-callee invocation edge */
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub call_site_va: u64,
    pub is_indirect: bool,
}

/* global call graph structure */
#[derive(Debug, Clone)]
pub struct CallGraph {
    pub graph: DiGraph<FunctionNode, CallEdge>,
    pub node_indices: Vec<NodeIndex>,
    pub total_width: usize,
    pub total_height: usize,
}

impl CallGraph {
    /*
     * build the inter-procedural call graph by disassembling all STT_FUNC symbols
     * and detecting direct and indirect CALL instructions.
     */
    pub fn build(elf: &ElfBinary) -> Self {
        let mut graph = DiGraph::new();
        let mut node_indices = Vec::new();
        let mut va_to_node: HashMap<u64, NodeIndex> = HashMap::new();

        let func_symbols = elf.find_function_symbols();

        /* create graph nodes for each function symbol */
        for (i, sym) in func_symbols.iter().enumerate() {
            let file_offset = elf.va_to_offset(sym.st_value).unwrap_or(0);
            let name_len = sym.name.len().max(16);

            let node = FunctionNode {
                id: i,
                name: sym.name.clone(),
                va: sym.st_value,
                size: sym.st_size,
                file_offset,
                callers_count: 0,
                callees_count: 0,
                x: 0,
                y: 0,
                width: name_len + 6,
                height: 4,
                layer: 0,
            };

            let idx = graph.add_node(node);
            node_indices.push(idx);
            va_to_node.insert(sym.st_value, idx);
        }

        /* map PLT / GOT slot targets */
        let mut got_to_func_va = HashMap::new();
        for reloc in &elf.relocations {
            if reloc.is_plt {
                if let Some(ref sym_name) = reloc.sym_name {
                    if let Some(sym) = elf.find_symbol_by_name(sym_name) {
                        got_to_func_va.insert(reloc.r_offset, sym.st_value);
                    }
                }
            }
        }

        /* analyze instructions within each function to discover outgoing CALLs */
        for &caller_idx in &node_indices {
            let (caller_va, caller_size, caller_off) = {
                let n = &graph[caller_idx];
                (n.va, n.size, n.file_offset)
            };

            if caller_size == 0 || caller_off + caller_size as usize > elf.bytes.len() {
                continue;
            }

            let func_bytes = &elf.bytes[caller_off..caller_off + caller_size as usize];
            let instructions = disassemble_slice(func_bytes, caller_va, caller_off);

            for instr in instructions {
                if instr.is_call() {
                    let mut callee_node = None;
                    let is_indirect = instr.flow_control == FlowControl::IndirectCall;

                    /* 1. Direct branch target */
                    if let Some(target) = instr.near_branch_target() {
                        if let Some(&target_idx) = va_to_node.get(&target) {
                            callee_node = Some(target_idx);
                        }
                    }

                    /* 2. Indirect memory call via .got.plt */
                    if callee_node.is_none() && instr.is_ip_rel_memory() {
                        if let Some(mem_target) = instr.ip_rel_memory_address() {
                            if let Some(&resolved_va) = got_to_func_va.get(&mem_target) {
                                if let Some(&target_idx) = va_to_node.get(&resolved_va) {
                                    callee_node = Some(target_idx);
                                }
                            }
                        }
                    }

                    if let Some(dst_idx) = callee_node {
                        graph.add_edge(
                            caller_idx,
                            dst_idx,
                            CallEdge {
                                call_site_va: instr.va,
                                is_indirect,
                            },
                        );
                        graph[caller_idx].callees_count += 1;
                        graph[dst_idx].callers_count += 1;
                    }
                }
            }
        }

        /* compute 2D hierarchical positions */
        let (total_w, total_h) = layout_callgraph(&mut graph, &node_indices);

        Self {
            graph,
            node_indices,
            total_width: total_w,
            total_height: total_h,
        }
    }
}

/* compute 2D hierarchical layout coordinates for call-graph nodes */
fn layout_callgraph(
    graph: &mut DiGraph<FunctionNode, CallEdge>,
    node_indices: &[NodeIndex],
) -> (usize, usize) {
    if node_indices.is_empty() {
        return (0, 0);
    }

    /* identify root nodes (functions with 0 callers, e.g. _start or main) */
    let mut roots: Vec<NodeIndex> = node_indices
        .iter()
        .copied()
        .filter(|&n| graph[n].callers_count == 0)
        .collect();

    if roots.is_empty() {
        roots.push(node_indices[0]);
    }

    let mut layers: Vec<Vec<NodeIndex>> = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    for &root in &roots {
        queue.push_back((root, 0usize));
        visited.insert(root);
    }

    while let Some((node, layer)) = queue.pop_front() {
        while layers.len() <= layer {
            layers.push(Vec::new());
        }
        layers[layer].push(node);

        for succ in graph.neighbors(node) {
            if !visited.contains(&succ) {
                visited.insert(succ);
                queue.push_back((succ, layer + 1));
            }
        }
    }

    /* append any remaining unvisited disconnected nodes */
    for &node in node_indices {
        if !visited.contains(&node) {
            let _layer = layers.len();
            layers.push(vec![node]);
        }
    }

    let mut cur_y = 2i32;
    let col_gap = 4i32;
    let row_gap = 4i32;
    let mut max_w = 0usize;

    for (layer_idx, layer_nodes) in layers.iter().enumerate() {
        let mut cur_x = 4i32;
        let mut max_h = 4usize;

        for &node in layer_nodes {
            let n = &mut graph[node];
            n.layer = layer_idx;
            n.x = cur_x;
            n.y = cur_y;

            cur_x += n.width as i32 + col_gap;
            if n.height > max_h {
                max_h = n.height;
            }
        }

        if cur_x as usize > max_w {
            max_w = cur_x as usize;
        }

        cur_y += max_h as i32 + row_gap;
    }

    (max_w + 10, cur_y as usize + 4)
}
