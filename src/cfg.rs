/* basic-block control-flow graph (CFG) analysis and 2d hierarchical layout */

use crate::arch::DecodedInstruction;
use crate::elf::SymbolInfo;
use iced_x86::FlowControl;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet, VecDeque};

/* directed edge classification for control flow transitions */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    Unconditional,
    BranchTaken, /* true condition branch path */
    Fallthrough, /* false condition fallthrough path */
}

/* a basic-block node containing a sequence of straight-line instructions */
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start_va: u64,
    pub end_va: u64,
    pub instructions: Vec<DecodedInstruction>,
    pub layer: usize,
    pub x: i32,
    pub y: i32,
    pub width: usize,
    pub height: usize,
}

/* 2d routed edge line segment for ratatui rendering */
#[derive(Debug, Clone)]
pub struct RenderEdge {
    pub from_id: usize,
    pub to_id: usize,
    pub edge_type: EdgeType,
    pub points: Vec<(i32, i32)>,
}

/* complete control-flow graph for a single STT_FUNC symbol */
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub func_name: String,
    pub func_va: u64,
    pub graph: DiGraph<BasicBlock, EdgeType>,
    pub node_indices: Vec<NodeIndex>,
    pub topo_order: Vec<usize>, /* block ids sorted in topological / execution order */
    pub edges_render: Vec<RenderEdge>,
    pub total_width: usize,
    pub total_height: usize,
}

impl ControlFlowGraph {
    /*
     * construct a CFG for a function symbol by executing a two-pass basic-block splitting algorithm.
     *
     * In Pass 1, leader instructions are identified:
     * 1. The function entry Virtual Address (VA).
     * 2. Any target VA of a ConditionalBranch or UnconditionalBranch.
     * 3. Any instruction immediately following a branch or Return.
     *
     * In Pass 2, instructions are partitioned into BasicBlock nodes,
     * and directed edges are added between predecessors and successors.
     */
    pub fn build(func_sym: &SymbolInfo, instructions: &[DecodedInstruction]) -> Option<Self> {
        let func_va = func_sym.st_value;
        let func_size = func_sym.st_size;

        /* filter instructions belonging to this function */
        let func_instrs: Vec<DecodedInstruction> = if func_size > 0 {
            instructions
                .iter()
                .filter(|i| i.va >= func_va && i.va < func_va + func_size)
                .cloned()
                .collect()
        } else {
            /* if symbol size is 0, collect until next RET or 100 instructions max */
            let mut instrs = Vec::new();
            let mut started = false;
            for i in instructions {
                if i.va == func_va {
                    started = true;
                }
                if started {
                    instrs.push(i.clone());
                    if i.is_return() || instrs.len() >= 80 {
                        break;
                    }
                }
            }
            instrs
        };

        if func_instrs.is_empty() {
            return None;
        }

        /* pass 1: identify block leaders */
        let mut leaders = HashSet::new();
        leaders.insert(func_instrs[0].va); /* entry VA */

        let va_set: HashSet<u64> = func_instrs.iter().map(|i| i.va).collect();

        for (idx, instr) in func_instrs.iter().enumerate() {
            let flow = instr.flow_control;
            match flow {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    if let Some(target) = instr.near_branch_target() {
                        if va_set.contains(&target) {
                            leaders.insert(target);
                        }
                    }
                    /* instruction following branch is a leader */
                    if idx + 1 < func_instrs.len() {
                        leaders.insert(func_instrs[idx + 1].va);
                    }
                }
                FlowControl::Return | FlowControl::Interrupt => {
                    /* instruction following return is a leader */
                    if idx + 1 < func_instrs.len() {
                        leaders.insert(func_instrs[idx + 1].va);
                    }
                }
                _ => {}
            }
        }

        /* pass 2: partition instructions into basic blocks */
        let mut blocks = Vec::new();
        let mut cur_instrs: Vec<DecodedInstruction> = Vec::new();
        let mut cur_block_id = 0;

        for instr in &func_instrs {
            if leaders.contains(&instr.va) && !cur_instrs.is_empty() {
                /* finish current block */
                let start_va = cur_instrs[0].va;
                let end_va = cur_instrs.last().unwrap().va + cur_instrs.last().unwrap().len as u64;
                blocks.push(BasicBlock {
                    id: cur_block_id,
                    start_va,
                    end_va,
                    instructions: cur_instrs,
                    layer: 0,
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                });
                cur_block_id += 1;
                cur_instrs = Vec::new();
            }
            cur_instrs.push(instr.clone());
        }

        if !cur_instrs.is_empty() {
            let start_va = cur_instrs[0].va;
            let end_va = cur_instrs.last().unwrap().va + cur_instrs.last().unwrap().len as u64;
            blocks.push(BasicBlock {
                id: cur_block_id,
                start_va,
                end_va,
                instructions: cur_instrs,
                layer: 0,
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            });
        }

        if blocks.is_empty() {
            return None;
        }

        /* map start_va to block index */
        let va_to_block_idx: HashMap<u64, usize> =
            blocks.iter().enumerate().map(|(i, b)| (b.start_va, i)).collect();

        /* build petgraph DiGraph */
        let mut graph = DiGraph::new();
        let mut node_indices = Vec::with_capacity(blocks.len());
        for block in &blocks {
            node_indices.push(graph.add_node(block.clone()));
        }

        /* populate directed edges based on block terminators */
        for (i, block) in blocks.iter().enumerate() {
            let terminator = block.instructions.last().unwrap();
            let flow = terminator.flow_control;
            let next_instr_va = terminator.va + terminator.len as u64;

            match flow {
                FlowControl::ConditionalBranch => {
                    /* true path (branch taken) */
                    if let Some(target) = terminator.near_branch_target() {
                        if let Some(&tgt_idx) = va_to_block_idx.get(&target) {
                            graph.add_edge(
                                node_indices[i],
                                node_indices[tgt_idx],
                                EdgeType::BranchTaken,
                            );
                        }
                    }
                    /* false path (fallthrough) */
                    if let Some(&next_idx) = va_to_block_idx.get(&next_instr_va) {
                        graph.add_edge(
                            node_indices[i],
                            node_indices[next_idx],
                            EdgeType::Fallthrough,
                        );
                    }
                }
                FlowControl::UnconditionalBranch => {
                    /* unconditional jump */
                    if let Some(target) = terminator.near_branch_target() {
                        if let Some(&tgt_idx) = va_to_block_idx.get(&target) {
                            graph.add_edge(
                                node_indices[i],
                                node_indices[tgt_idx],
                                EdgeType::Unconditional,
                            );
                        }
                    }
                }
                FlowControl::Return | FlowControl::Interrupt => {
                    /* terminal block: no outgoing edges */
                }
                _ => {
                    /* standard sequential fallthrough */
                    if let Some(&next_idx) = va_to_block_idx.get(&next_instr_va) {
                        graph.add_edge(
                            node_indices[i],
                            node_indices[next_idx],
                            EdgeType::Unconditional,
                        );
                    }
                }
            }
        }

        /* compute topological / BFS ordering and hierarchical 2D layout */
        let (topo_order, render_edges, total_w, total_h) =
            compute_hierarchical_layout(&mut graph, &node_indices);

        Some(ControlFlowGraph {
            func_name: func_sym.name.clone(),
            func_va,
            graph,
            node_indices,
            topo_order,
            edges_render: render_edges,
            total_width: total_w,
            total_height: total_h,
        })
    }
}

/* compute hierarchical 2D layout coordinates for basic blocks and route edges */
fn compute_hierarchical_layout(
    graph: &mut DiGraph<BasicBlock, EdgeType>,
    node_indices: &[NodeIndex],
) -> (Vec<usize>, Vec<RenderEdge>, usize, usize) {
    if node_indices.is_empty() {
        return (Vec::new(), Vec::new(), 0, 0);
    }

    /* 1. Calculate dimensions for each block */
    for &idx in node_indices {
        let block = &mut graph[idx];
        let mut max_text_len = 12; /* header length */
        for instr in &block.instructions {
            let line_len = format!("0x{:x}: {}", instr.va, instr.disasm).len();
            if line_len > max_text_len {
                max_text_len = line_len;
            }
        }
        block.width = max_text_len + 4; /* border padding */
        block.height = block.instructions.len() + 2; /* header + border */
    }

    /* 2. Assign layers using BFS from entry node */
    let mut layers: Vec<Vec<NodeIndex>> = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();

    let entry = node_indices[0];
    queue.push_back((entry, 0usize));
    visited.insert(entry);

    let mut node_layer: HashMap<NodeIndex, usize> = HashMap::new();

    while let Some((node, layer)) = queue.pop_front() {
        node_layer.insert(node, layer);
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

    /* handle any disconnected blocks */
    for &node in node_indices {
        if !visited.contains(&node) {
            let layer = layers.len();
            layers.push(vec![node]);
            node_layer.insert(node, layer);
        }
    }

    /* 3. Assign 2D coordinates (x, y) */
    let mut cur_y = 2i32;
    let col_gap = 6i32;
    let row_gap = 4i32;
    let mut max_total_w = 0usize;

    for layer_nodes in &layers {
        let mut max_h_in_layer = 0usize;
        let mut cur_x = 4i32;

        for &node in layer_nodes {
            let block = &mut graph[node];
            block.layer = *node_layer.get(&node).unwrap_or(&0);
            block.x = cur_x;
            block.y = cur_y;

            if block.height > max_h_in_layer {
                max_h_in_layer = block.height;
            }
            cur_x += block.width as i32 + col_gap;
        }

        if cur_x as usize > max_total_w {
            max_total_w = cur_x as usize;
        }

        cur_y += max_h_in_layer as i32 + row_gap;
    }

    let total_height = cur_y as usize + 4;
    let total_width = max_total_w + 10;

    /* 4. Collect topological / block order */
    let mut topo_order = Vec::new();
    for layer_nodes in &layers {
        for &node in layer_nodes {
            topo_order.push(graph[node].id);
        }
    }

    /* 5. Route simple orthogonal render edges */
    let mut render_edges = Vec::new();
    for edge in graph.edge_indices() {
        if let Some((src, dst)) = graph.edge_endpoints(edge) {
            let edge_type = graph[edge];
            let src_block = &graph[src];
            let dst_block = &graph[dst];

            let start_x = src_block.x + (src_block.width as i32 / 2);
            let start_y = src_block.y + src_block.height as i32;

            let end_x = dst_block.x + (dst_block.width as i32 / 2);
            let end_y = dst_block.y;

            let mut points = Vec::new();
            points.push((start_x, start_y));
            let mid_y = start_y + (end_y - start_y) / 2;
            points.push((start_x, mid_y));
            points.push((end_x, mid_y));
            points.push((end_x, end_y));

            render_edges.push(RenderEdge {
                from_id: src_block.id,
                to_id: dst_block.id,
                edge_type,
                points,
            });
        }
    }

    (topo_order, render_edges, total_width, total_height)
}
