/* ratatui modal TUI renderer: 3-pane layout, synchronized hex dump, and inspectors */

use crate::audit::{MitigationStatus, SecurityReport};
use crate::callgraph::CallGraph;
use crate::cfg::{ControlFlowGraph, EdgeType};
use crate::codecave::CodeCave;
use crate::debug::{BreakpointManager, CpuRegisters};
use crate::diff::BinaryDiff;
use crate::dwarf::DwarfIndex;
use crate::elf::{format_em_machine, format_et_type, format_p_flags, format_sh_flags, ElfBinary};
use crate::live::LiveSession;
use crate::memmap::MemoryMap;
use crate::reloc::RelocEntry;
use crate::strings::StringEntry;
use crate::symbols::UnifiedSymbol;
use crate::theme::{to_color, Theme};
use crate::vim::{JumpStack, UndoStack, VimMode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Row, Table},
    Frame,
};

/* active central viewport mode */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CenterView {
    Disassembly,
    Cfg,
    Headers,
    Strings,
    Reloc,
    MemoryMap,
    CallGraph,
    Diff,
    LiveDebug,
}

/* active modal popup overlay */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    Xref(u64),          /* target VA for incoming XREFs */
    Audit,              /* security audit dashboard */
    SymbolSearch,       /* fuzzy symbol search */
    CodeCaves,          /* code cave table */
}

/* primary application state coordinating models and views */
pub struct AppState {
    pub elf: ElfBinary,
    pub mode: VimMode,
    pub center_view: CenterView,
    pub modal: ActiveModal,

    /* navigation cursor positions */
    pub cursor_file_offset: usize,
    pub cursor_va: u64,
    pub sidebar_index: usize,
    pub center_cursor_index: usize,
    pub center_scroll_offset: usize,
    pub hex_scroll_offset: usize,
    pub active_pane: usize, /* 0: sidebar, 1: center, 2: hex */

    /* CFG state */
    pub cfg: Option<ControlFlowGraph>,
    pub cfg_selected_block_idx: usize,
    pub cfg_selected_instr_idx: usize,
    pub cfg_scroll_x: i32,
    pub cfg_scroll_y: i32,

    /* CallGraph state */
    pub callgraph: Option<CallGraph>,
    pub cg_selected_node_idx: usize,
    pub cg_scroll_x: i32,
    pub cg_scroll_y: i32,

    /* diff state */
    pub diff: Option<BinaryDiff>,

    /* live debug state */
    pub live_session: Option<LiveSession>,
    pub bp_manager: BreakpointManager,
    pub cpu_regs: Option<CpuRegisters>,

    /* cached inspectors */
    pub strings_list: Vec<StringEntry>,
    pub reloc_list: Vec<RelocEntry>,
    pub memory_map: MemoryMap,
    pub security_report: SecurityReport,
    pub dwarf_index: DwarfIndex,
    pub caves_list: Vec<CodeCave>,

    /* modal cursors */
    pub modal_cursor: usize,
    pub symbol_query: String,
    pub filtered_symbols: Vec<UnifiedSymbol>,

    /* inline input buffers */
    pub input_buffer: String,
    pub command_buffer: String,
    pub search_buffer: String,

    /* statusline diagnostic message */
    pub status_message: String,
    pub is_error_message: bool,

    /* stacks */
    pub jump_stack: JumpStack,
    pub undo_stack: UndoStack,

    /* source-line annotation toggle */
    pub show_source_lines: bool,

    /* cached disassembly window for zero-latency frame rendering */
    pub cached_disasm: Vec<crate::arch::DecodedInstruction>,
    pub cached_disasm_anchor: Option<(usize, usize)>,
    pub cached_func_symbols: Vec<crate::elf::SymbolInfo>,
    pub cached_xref_map: Option<crate::xref::XrefMap>,

    /* pending key chord state machine (e.g. 'g', 'c', ']', '[') */
    pub pending_chord: Option<char>,

    /* customizable color theme and syntax palette */
    pub theme: Theme,

    /* high-performance instruction cache mapping file offsets to decoded instructions */
    pub instruction_cache: crate::arch::InstructionCache,

    /* virtualized disassembly viewport anchor */
    pub disasm_viewport_top: usize,

    /* asynchronous parallel background worker spinner state */
    pub bg_task_spinner: usize,
    pub bg_task_status: Option<String>,
}

impl AppState {
    /* construct initial application state from loaded ELF */
    pub fn new(elf: ElfBinary) -> Self {
        let entry_va = elf.entry;
        let entry_offset = elf.va_to_offset(entry_va).unwrap_or(0);
        let mem_map = MemoryMap::build(&elf);
        let sec_report = SecurityReport::scan(&elf);
        let dwarf = DwarfIndex::parse_from_bytes(&elf.bytes);
        let caves = crate::codecave::scan_code_caves(&elf, 16);
        let cached_funcs: Vec<crate::elf::SymbolInfo> = elf.find_function_symbols().into_iter().cloned().collect();

        let mut inst_cache = crate::arch::InstructionCache::new(4096);
        inst_cache.preindex_range(&elf.bytes, entry_offset, entry_va, 300);

        let mut state = Self {
            elf,
            mode: VimMode::Normal,
            center_view: CenterView::Disassembly,
            modal: ActiveModal::None,

            cursor_file_offset: entry_offset,
            cursor_va: entry_va,
            sidebar_index: 0,
            center_cursor_index: 0,
            center_scroll_offset: 0,
            hex_scroll_offset: entry_offset.saturating_sub(entry_offset % 16),
            active_pane: 1, /* start in center pane */

            cfg: None,
            cfg_selected_block_idx: 0,
            cfg_selected_instr_idx: 0,
            cfg_scroll_x: 0,
            cfg_scroll_y: 0,

            callgraph: None,
            cg_selected_node_idx: 0,
            cg_scroll_x: 0,
            cg_scroll_y: 0,

            diff: None,

            live_session: None,
            bp_manager: BreakpointManager::new(),
            cpu_regs: None,

            strings_list: Vec::new(),
            reloc_list: Vec::new(),
            memory_map: mem_map,
            security_report: sec_report,
            dwarf_index: dwarf,
            caves_list: caves,

            modal_cursor: 0,
            symbol_query: String::new(),
            filtered_symbols: Vec::new(),

            input_buffer: String::new(),
            command_buffer: String::new(),
            search_buffer: String::new(),

            status_message: "Press '?' for help, ':' for command mode".to_string(),
            is_error_message: false,

            jump_stack: JumpStack::new(),
            undo_stack: UndoStack::new(),

            show_source_lines: true,

            cached_disasm: Vec::new(),
            cached_disasm_anchor: None,
            cached_func_symbols: cached_funcs,
            cached_xref_map: None,
            pending_chord: None,

            theme: Theme::nord(),
            instruction_cache: inst_cache,
            disasm_viewport_top: entry_offset,
            bg_task_spinner: 0,
            bg_task_status: None,
        };

        state.update_disassembly_cache();
        state
    }

    /*
     * update virtualized disassembly viewport around current cursor location.
     * Uses InstructionCache to decode and fetch strictly the ~45 lines needed for the viewport,
     * maintaining sub-millisecond frame rendering without re-decoding whole sections.
     */
    pub fn update_disassembly_cache(&mut self) {
        let (start_off, size, base_va) = match self.elf.find_section_at_offset(self.cursor_file_offset) {
            Some(s) if s.is_executable => (s.sh_offset as usize, s.sh_size as usize, s.sh_addr),
            _ => {
                let first_exec = self.elf.sections.iter().find(|s| s.is_executable && s.sh_size > 0);
                match first_exec {
                    Some(s) => (s.sh_offset as usize, s.sh_size as usize, s.sh_addr),
                    None => (0, self.elf.bytes.len().min(4096), 0x400000),
                }
            }
        };

        let viewport_lines = 45;

        /* if viewport top is outside the current executable section, reset to cursor */
        if self.disasm_viewport_top < start_off || self.disasm_viewport_top >= start_off + size {
            self.disasm_viewport_top = self.cursor_file_offset;
        }

        /* if cursor scrolled above viewport top, bring viewport top up to cursor */
        if self.cursor_file_offset < self.disasm_viewport_top {
            self.disasm_viewport_top = self.cursor_file_offset;
        }

        /* pre-decode a localized window starting at disasm_viewport_top */
        let top_va = if base_va > 0 && self.disasm_viewport_top >= start_off {
            base_va + (self.disasm_viewport_top - start_off) as u64
        } else {
            self.elf.offset_to_va(self.disasm_viewport_top).unwrap_or(0x400000)
        };

        self.instruction_cache.preindex_range(&self.elf.bytes, self.disasm_viewport_top, top_va, viewport_lines);

        let mut lines = Vec::with_capacity(viewport_lines);
        let mut cur_off = self.disasm_viewport_top;
        let mut cur_va = top_va;

        while cur_off < self.elf.bytes.len() && lines.len() < viewport_lines {
            if let Some(instr) = self.instruction_cache.get_or_decode(&self.elf.bytes, cur_off, cur_va) {
                let len = instr.len;
                cur_off += len;
                cur_va += len as u64;
                lines.push(instr);
            } else {
                break;
            }
        }

        /* if cursor is beyond bottom of current viewport window, scroll viewport down */
        if let Some(last) = lines.last() {
            if self.cursor_file_offset >= last.file_offset + last.len {
                self.disasm_viewport_top = self.cursor_file_offset;
                let new_top_va = if base_va > 0 && self.disasm_viewport_top >= start_off {
                    base_va + (self.disasm_viewport_top - start_off) as u64
                } else {
                    self.elf.offset_to_va(self.disasm_viewport_top).unwrap_or(0x400000)
                };
                self.instruction_cache.preindex_range(&self.elf.bytes, self.disasm_viewport_top, new_top_va, viewport_lines);
                lines.clear();
                let mut c_off = self.disasm_viewport_top;
                let mut c_va = new_top_va;
                while c_off < self.elf.bytes.len() && lines.len() < viewport_lines {
                    if let Some(instr) = self.instruction_cache.get_or_decode(&self.elf.bytes, c_off, c_va) {
                        let len = instr.len;
                        c_off += len;
                        c_va += len as u64;
                        lines.push(instr);
                    } else {
                        break;
                    }
                }
            }
        }

        self.cached_disasm = lines;
        self.cached_disasm_anchor = Some((start_off, size));
    }

    /* set statusline notification */
    pub fn set_status(&mut self, msg: &str, is_error: bool) {
        self.status_message = msg.to_string();
        self.is_error_message = is_error;
    }

    /* synchronize hex scroll offset to cursor offset */
    pub fn sync_hex_scroll(&mut self) {
        let row_start = self.cursor_file_offset.saturating_sub(self.cursor_file_offset % 16);
        if row_start < self.hex_scroll_offset || row_start >= self.hex_scroll_offset + 320 {
            self.hex_scroll_offset = row_start.saturating_sub(80);
        }
    }
}

/* render full TUI frame */
pub fn render_ui(frame: &mut Frame, state: &mut AppState) {
    let size = frame.area();

    /* root layout: 3-pane main body + 1-row status line */
    let root_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(size);

    /* 3-column horizontal split: Sidebar (25%), Center (48%), Hex/ASCII (27%) */
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(49),
            Constraint::Percentage(27),
        ])
        .split(root_layout[0]);

    render_sidebar(frame, state, columns[0]);
    render_center(frame, state, columns[1]);
    render_hex_dump(frame, state, columns[2]);
    render_status_line(frame, state, root_layout[1]);

    /* render modal overlays if active */
    match &state.modal {
        ActiveModal::Xref(va) => render_xref_modal(frame, state, *va, size),
        ActiveModal::Audit => render_audit_modal(frame, state, size),
        ActiveModal::SymbolSearch => render_symbol_search_modal(frame, state, size),
        ActiveModal::CodeCaves => render_caves_modal(frame, state, size),
        ActiveModal::None => {}
    }
}

/* render left sidebar containing sections and symbols */
fn render_sidebar(frame: &mut Frame, state: &AppState, area: Rect) {
    let is_focused = state.active_pane == 0;
    let border_color = if is_focused {
        to_color(state.theme.palette.border_active)
    } else {
        to_color(state.theme.palette.border)
    };

    let sidebar_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    /* 1. Sections list */
    let sec_items: Vec<ListItem> = state
        .elf
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let exec_tag = if s.is_executable { "[X]" } else { "   " };
            let style = if is_focused && state.sidebar_index == i {
                Style::default()
                    .fg(to_color(state.theme.palette.cursor_fg))
                    .bg(to_color(state.theme.palette.cursor_bg))
                    .add_modifier(Modifier::BOLD)
            } else if s.is_executable {
                Style::default().fg(to_color(state.theme.palette.entropy_low))
            } else {
                Style::default().fg(to_color(state.theme.palette.foreground))
            };
            ListItem::new(format!("{:2} {} {:<14} 0x{:08x}", i, exec_tag, s.name, s.sh_addr)).style(style)
        })
        .collect();

    let sec_list = List::new(sec_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" [1] Sections (SHF_EXECINSTR) "),
    );
    frame.render_widget(sec_list, sidebar_layout[0]);

    /* 2. Functions (STT_FUNC) list */
    let func_items: Vec<ListItem> = state
        .cached_func_symbols
        .iter()
        .take(100)
        .map(|f| {
            let style = Style::default().fg(to_color(state.theme.palette.branch_target));
            ListItem::new(format!("0x{:08x} {}", f.st_value, f.name)).style(style)
        })
        .collect();

    let func_list = List::new(func_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" Functions ({}) ", state.cached_func_symbols.len())),
    );
    frame.render_widget(func_list, sidebar_layout[1]);
}

/* render central pane based on active view mode */
fn render_center(frame: &mut Frame, state: &mut AppState, area: Rect) {
    let is_focused = state.active_pane == 1;
    let border_color = if is_focused {
        to_color(state.theme.palette.border_active)
    } else {
        to_color(state.theme.palette.border)
    };

    let block_title = match state.center_view {
        CenterView::Disassembly => " [2] Disassembly (x86_64 Intel) ",
        CenterView::Cfg => " [2] Control-Flow Graph (CFG) ",
        CenterView::Headers => " [2] Structural Inspector (Ehdr, Phdr, Shdr) ",
        CenterView::Strings => " [2] Strings Inspector (.rodata, .dynstr) ",
        CenterView::Reloc => " [2] PLT/GOT Relocations & Hooking ",
        CenterView::MemoryMap => " [2] Visual Memory Map & Entropy ",
        CenterView::CallGraph => " [2] Inter-Procedural Call Graph ",
        CenterView::Diff => " [2] Binary Hex Diff ",
        CenterView::LiveDebug => " [2] Live Process Debugger (ptrace) ",
    };

    let inner_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(block_title);

    let inner_area = inner_block.inner(area);
    frame.render_widget(inner_block, area);

    match state.center_view {
        CenterView::Disassembly => render_disassembly_view(frame, state, inner_area),
        CenterView::Cfg => render_cfg_view(frame, state, inner_area),
        CenterView::Headers => render_headers_view(frame, state, inner_area),
        CenterView::Strings => render_strings_view(frame, state, inner_area),
        CenterView::Reloc => render_reloc_view(frame, state, inner_area),
        CenterView::MemoryMap => render_memmap_view(frame, state, inner_area),
        CenterView::CallGraph => render_callgraph_view(frame, state, inner_area),
        CenterView::Diff => render_diff_view(frame, state, inner_area),
        CenterView::LiveDebug => render_live_debug_view(frame, state, inner_area),
    }
}

/* render linear disassembly view using virtualized viewport and theme palette */
fn render_disassembly_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let visible_rows = area.height as usize;
    if state.cached_disasm.is_empty() {
        let p = Paragraph::new("No executable instructions found in current section.")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(p, area);
        return;
    }

    let mut lines = Vec::with_capacity(visible_rows);

    for instr in state.cached_disasm.iter().take(visible_rows) {
        let is_selected = instr.file_offset <= state.cursor_file_offset && state.cursor_file_offset < instr.file_offset + instr.len;

        /* optional DWARF source line annotation */
        if state.show_source_lines {
            if let Some(src_loc) = state.dwarf_index.lookup(instr.va) {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  ; {}:{}", src_loc.file_path, src_loc.line),
                        Style::default().fg(to_color(state.theme.palette.source_line)),
                    ),
                ]));
            }
        }

        /* if in ASM_PATCH mode on selected line, show inline input prompt */
        if is_selected && state.mode == VimMode::AsmPatch {
            lines.push(Line::from(vec![
                Span::styled(format!("0x{:08x}: ", instr.va), Style::default().fg(Color::Yellow)),
                Span::styled(format!("[PATCH: {}_]", state.input_buffer), Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
            continue;
        }

        let mut spans = Vec::with_capacity(6);
        spans.push(Span::styled(
            format!("0x{:08x}  ", instr.va),
            Style::default().fg(to_color(state.theme.palette.hex_offset)),
        ));
        spans.push(Span::styled(
            format!("{:<18} ", &instr.formatted_hex),
            Style::default().fg(to_color(state.theme.palette.hex_nonprintable)),
        ));

        spans.extend(instr.format_spans(&state.theme.palette, is_selected));
        lines.push(Line::from(spans));
    }

    let p = Paragraph::new(lines);
    frame.render_widget(p, area);
}

/* render 2D hierarchical box-drawing CFG */
fn render_cfg_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let cfg = match state.cfg.as_ref() {
        Some(c) => c,
        None => {
            let msg = Paragraph::new("No CFG loaded. Focus on a function and press 'gf' or ':cfg' to generate CFG.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let ox = state.cfg_scroll_x;
    let oy = state.cfg_scroll_y;

    /* draw basic block boxes */
    for (node_idx, block) in cfg.graph.node_weights().enumerate() {
        let is_block_focused = node_idx == state.cfg_selected_block_idx;

        let bx = block.x - ox;
        let by = block.y - oy;
        let bw = block.width as i32;
        let bh = block.height as i32;

        if bx + bw < 0 || bx >= area.width as i32 || by + bh < 0 || by >= area.height as i32 {
            continue;
        }

        let rect_x = bx.max(0) as u16;
        let rect_y = by.max(0) as u16;
        let rect_w = (bw as u16).min(area.width.saturating_sub(rect_x));
        let rect_h = (bh as u16).min(area.height.saturating_sub(rect_y));

        let block_rect = Rect::new(area.x + rect_x, area.y + rect_y, rect_w, rect_h);

        let border_color = if is_block_focused { Color::Yellow } else { Color::White };
        let box_widget = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" Block #{} (0x{:x}) ", block.id, block.start_va));

        frame.render_widget(box_widget, block_rect);

        /* render instructions inside box */
        let inner_rect = Rect::new(
            block_rect.x + 1,
            block_rect.y + 1,
            block_rect.width.saturating_sub(2),
            block_rect.height.saturating_sub(2),
        );

        let mut lines = Vec::new();
        for (i_idx, instr) in block.instructions.iter().enumerate() {
            let is_instr_focused = is_block_focused && i_idx == state.cfg_selected_instr_idx;

            if is_instr_focused && state.mode == VimMode::AsmPatch {
                lines.push(Line::from(vec![
                    Span::styled(format!("[PATCH: {}_]", state.input_buffer), Style::default().fg(Color::Black).bg(Color::Yellow)),
                ]));
                continue;
            }

            let style = if is_instr_focused {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::LightCyan)
            };

            lines.push(Line::from(vec![
                Span::styled(format!("0x{:x}: ", instr.va), Style::default().fg(Color::DarkGray)),
                Span::styled(instr.disasm.clone(), style),
            ]));
        }

        frame.render_widget(Paragraph::new(lines), inner_rect);
    }

    /* draw colored edges */
    for edge in &cfg.edges_render {
        let edge_color = match edge.edge_type {
            EdgeType::BranchTaken => Color::Green,
            EdgeType::Fallthrough => Color::Red,
            EdgeType::Unconditional => Color::Cyan,
        };

        for window in edge.points.windows(2) {
            let (p1, p2) = (window[0], window[1]);
            let x1 = p1.0 - ox;
            let y1 = p1.1 - oy;
            let x2 = p2.0 - ox;
            let y2 = p2.1 - oy;

            if x1 == x2 {
                /* vertical segment */
                let min_y = y1.min(y2);
                let max_y = y1.max(y2);
                for y in min_y..=max_y {
                    if x1 >= 0 && x1 < area.width as i32 && y >= 0 && y < area.height as i32 {
                        let cell_rect = Rect::new(area.x + x1 as u16, area.y + y as u16, 1, 1);
                        frame.render_widget(Paragraph::new("│").style(Style::default().fg(edge_color)), cell_rect);
                    }
                }
            } else if y1 == y2 {
                /* horizontal segment */
                let min_x = x1.min(x2);
                let max_x = x1.max(x2);
                for x in min_x..=max_x {
                    if x >= 0 && x < area.width as i32 && y1 >= 0 && y1 < area.height as i32 {
                        let cell_rect = Rect::new(area.x + x as u16, area.y + y1 as u16, 1, 1);
                        frame.render_widget(Paragraph::new("─").style(Style::default().fg(edge_color)), cell_rect);
                    }
                }
            }
        }
    }
}

/* render Structural Header Inspector */
fn render_headers_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .elf
        .fields
        .iter()
        .enumerate()
        .skip(state.center_scroll_offset)
        .take(area.height as usize)
        .map(|(i, f)| {
            let is_selected = i == state.center_cursor_index;
            let val_str = if is_selected && state.mode == VimMode::FieldEdit {
                format!("[EDIT: {}_]", state.input_buffer)
            } else if f.is_flags {
                if f.field_name == "p_flags" {
                    format_p_flags(f.current_value as u32)
                } else if f.field_name == "sh_flags" {
                    format_sh_flags(f.current_value)
                } else {
                    format!("0x{:x}", f.current_value)
                }
            } else if f.field_name == "e_type" {
                format_et_type(f.current_value as u16).to_string()
            } else if f.field_name == "e_machine" {
                format_em_machine(f.current_value as u16).to_string()
            } else {
                format!("0x{:x} ({})", f.current_value, f.current_value)
            };

            let row_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                f.struct_name.clone(),
                f.field_name.clone(),
                format!("0x{:04x}", f.file_offset),
                format!("{:?}", f.width),
                val_str,
                f.description.clone(),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(22),
        Constraint::Length(14),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Percentage(26),
        Constraint::Percentage(24),
    ];

    let header = Row::new(vec!["Struct", "Member", "Offset", "Width", "Value", "Description"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths).header(header);
    frame.render_widget(table, area);
}

/* render Strings Inspector view */
fn render_strings_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .strings_list
        .iter()
        .enumerate()
        .skip(state.center_scroll_offset)
        .take(area.height as usize)
        .map(|(i, s)| {
            let is_selected = i == state.center_cursor_index;
            let display_str = if is_selected && state.mode == VimMode::StringEdit {
                format!("[EDIT: {}_]", state.input_buffer)
            } else {
                crate::strings::escape_string(&s.content)
            };

            let row_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                format!("0x{:08x}", s.va),
                format!("0x{:04x}", s.file_offset),
                s.section_name.clone(),
                format!("{} (cap {})", s.content.len(), s.max_slot_len),
                format!("{}", s.xref_count),
                display_str,
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Percentage(52),
    ];

    let header = Row::new(vec!["VA", "Offset", "Section", "Length", "XREFs", "Literal"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths).header(header);
    frame.render_widget(table, area);
}

/* render PLT/GOT Relocations view */
fn render_reloc_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .reloc_list
        .iter()
        .enumerate()
        .skip(state.center_scroll_offset)
        .take(area.height as usize)
        .map(|(i, r)| {
            let is_selected = i == state.center_cursor_index;
            let target_str = if is_selected && state.mode == VimMode::HookEdit {
                format!("[HOOK: {}_]", state.input_buffer)
            } else {
                format!("0x{:08x}", r.current_target_va)
            };

            let row_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                format!("0x{:04x}", r.file_offset),
                r.r_type_name.clone(),
                r.sym_name.clone(),
                format!("0x{:08x}", r.r_offset),
                target_str,
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Percentage(30),
        Constraint::Length(14),
        Constraint::Percentage(25),
    ];

    let header = Row::new(vec!["Offset", "Reloc Type", "Symbol Name", "GOT Slot VA", "Target VA"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths).header(header);
    frame.render_widget(table, area);
}

/* render Visual Memory Map view */
fn render_memmap_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .memory_map
        .items
        .iter()
        .enumerate()
        .skip(state.center_scroll_offset)
        .take(area.height as usize)
        .map(|(i, item)| {
            let is_selected = i == state.center_cursor_index;
            let row_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                item.name.clone(),
                format!("0x{:08x}", item.va_start),
                format!("0x{:04x}", item.file_offset),
                format!("{} B", item.file_size),
                item.permissions.clone(),
                format!("{:.2}", item.entropy),
                item.translation_formula.clone(),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(25),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Percentage(29),
    ];

    let header = Row::new(vec!["Segment / Section", "VA Start", "Offset", "Size", "Perm", "Entropy", "Translation Formula"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths).header(header);
    frame.render_widget(table, area);
}

/* render Inter-Procedural Call Graph view */
fn render_callgraph_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let cg = match state.callgraph.as_ref() {
        Some(c) => c,
        None => {
            let msg = Paragraph::new("No Call Graph generated. Press 'gc' or ':callgraph' to analyze functions.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let ox = state.cg_scroll_x;
    let oy = state.cg_scroll_y;

    for (node_idx, node) in cg.graph.node_weights().enumerate() {
        let is_selected = node_idx == state.cg_selected_node_idx;
        let nx = node.x - ox;
        let ny = node.y - oy;
        let nw = node.width as i32;
        let nh = node.height as i32;

        if nx + nw < 0 || nx >= area.width as i32 || ny + nh < 0 || ny >= area.height as i32 {
            continue;
        }

        let rect_x = nx.max(0) as u16;
        let rect_y = ny.max(0) as u16;
        let rect_w = (nw as u16).min(area.width.saturating_sub(rect_x));
        let rect_h = (nh as u16).min(area.height.saturating_sub(rect_y));

        let node_rect = Rect::new(area.x + rect_x, area.y + rect_y, rect_w, rect_h);
        let border_color = if is_selected { Color::Yellow } else { Color::Cyan };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(format!(" {} ", node.name));

        frame.render_widget(block, node_rect);

        let inner = Rect::new(
            node_rect.x + 1,
            node_rect.y + 1,
            node_rect.width.saturating_sub(2),
            node_rect.height.saturating_sub(2),
        );

        let lines = vec![
            Line::from(format!("Entry: 0x{:08x}", node.va)),
            Line::from(format!("Callers: {} | Callees: {}", node.callers_count, node.callees_count)),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

/* render Dual Hex Diff view */
fn render_diff_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let diff = match state.diff.as_ref() {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("No comparison binary loaded. Run ':diff <filepath>' to start hex diff.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let rows_count = area.height as usize;
    let mut lines_a = Vec::new();
    let mut lines_b = Vec::new();

    let cur_off = state.cursor_file_offset.saturating_sub(state.cursor_file_offset % 16);

    for row_idx in 0..rows_count {
        let off = cur_off + row_idx * 16;
        if off >= state.elf.bytes.len() && off >= diff.bytes_b.len() {
            break;
        }

        let mut spans_a = vec![Span::styled(format!("0x{:04x}: ", off), Style::default().fg(Color::DarkGray))];
        let mut spans_b = vec![Span::styled(format!("0x{:04x}: ", off), Style::default().fg(Color::DarkGray))];

        for i in 0..16 {
            let byte_a = state.elf.bytes.get(off + i).copied();
            let byte_b = diff.bytes_b.get(off + i).copied();

            let (style_a, style_b) = if byte_a == byte_b {
                (Style::default().fg(Color::DarkGray), Style::default().fg(Color::DarkGray))
            } else {
                (
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            };

            spans_a.push(Span::styled(format!("{:02x} ", byte_a.unwrap_or(0)), style_a));
            spans_b.push(Span::styled(format!("{:02x} ", byte_b.unwrap_or(0)), style_b));
        }

        lines_a.push(Line::from(spans_a));
        lines_b.push(Line::from(spans_b));
    }

    frame.render_widget(Paragraph::new(lines_a).block(Block::default().title(" Primary Binary ")), split[0]);
    frame.render_widget(Paragraph::new(lines_b).block(Block::default().title(format!(" Diff: {:?} ", diff.comparison_path))), split[1]);
}

/* render Live Process Debugger view */
fn render_live_debug_view(frame: &mut Frame, state: &AppState, area: Rect) {
    let regs = match state.cpu_regs {
        Some(r) => r,
        None => {
            let msg = Paragraph::new("No active ptrace session. Use ':attach <pid>' or 'gp' to attach to a process.")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(area);

    let reg_lines = vec![
        Line::from(format!("RAX: 0x{:016x}   RBX: 0x{:016x}   RCX: 0x{:016x}   RDX: 0x{:016x}", regs.rax, regs.rbx, regs.rcx, regs.rdx)),
        Line::from(format!("RSI: 0x{:016x}   RDI: 0x{:016x}   RBP: 0x{:016x}   RSP: 0x{:016x}", regs.rsi, regs.rdi, regs.rbp, regs.rsp)),
        Line::from(format!("R8:  0x{:016x}   R9:  0x{:016x}   R10: 0x{:016x}   R11: 0x{:016x}", regs.r8, regs.r9, regs.r10, regs.r11)),
        Line::from(format!("R12: 0x{:016x}   R13: 0x{:016x}   R14: 0x{:016x}   R15: 0x{:016x}", regs.r12, regs.r13, regs.r14, regs.r15)),
        Line::from(format!("RIP: 0x{:016x}   RFLAGS: 0x{:08x}", regs.rip, regs.rflags)),
    ];

    let reg_box = Paragraph::new(reg_lines).block(Block::default().borders(Borders::ALL).title(" CPU General-Purpose Registers (x86_64) "));
    frame.render_widget(reg_box, split[0]);

    /* active breakpoints list */
    let bp_items: Vec<ListItem> = state
        .bp_manager
        .breakpoints
        .values()
        .map(|bp| {
            ListItem::new(format!("Breakpoint @ 0x{:08x} (orig opcode: 0x{:02x})", bp.va, bp.original_byte))
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        })
        .collect();

    let bp_list = List::new(bp_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Active Software Breakpoints ({}) ", state.bp_manager.breakpoints.len())),
    );
    frame.render_widget(bp_list, split[1]);
}

/* render synchronized Hex and ASCII dump pane with zero-allocation byte formatting */
fn render_hex_dump(frame: &mut Frame, state: &AppState, area: Rect) {
    let is_focused = state.active_pane == 2;
    let border_color = if is_focused {
        to_color(state.theme.palette.border_active)
    } else {
        to_color(state.theme.palette.border)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(" [3] Hex / ASCII Dump ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows_count = inner.height as usize;
    let mut lines = Vec::with_capacity(rows_count);

    for row_idx in 0..rows_count {
        let row_offset = state.hex_scroll_offset + row_idx * 16;
        if row_offset >= state.elf.bytes.len() {
            break;
        }

        let mut spans = Vec::with_capacity(19);
        spans.push(Span::styled(
            format!("{:06x}  ", row_offset),
            Style::default().fg(to_color(state.theme.palette.hex_offset)),
        ));

        /* 16 hex byte pairs using static lookup table (zero heap allocations) */
        let mut ascii_chars = String::with_capacity(16);
        for col in 0..16 {
            let byte_off = row_offset + col;
            if byte_off < state.elf.bytes.len() {
                let b = state.elf.bytes[byte_off];
                let is_cursor = byte_off == state.cursor_file_offset;

                let style = if is_cursor {
                    Style::default()
                        .fg(to_color(state.theme.palette.cursor_fg))
                        .bg(to_color(state.theme.palette.cursor_bg))
                        .add_modifier(Modifier::BOLD)
                } else if b == 0x00 {
                    Style::default().fg(to_color(state.theme.palette.hex_zero))
                } else if b == 0x90 {
                    Style::default().fg(to_color(state.theme.palette.entropy_low)) /* NOP sled */
                } else {
                    Style::default().fg(to_color(state.theme.palette.hex_printable))
                };

                spans.push(Span::styled(crate::arch::HEX_TABLE[b as usize], style));

                if (0x20..=0x7e).contains(&b) {
                    ascii_chars.push(b as char);
                } else {
                    ascii_chars.push('.');
                }
            } else {
                spans.push(Span::raw("   "));
                ascii_chars.push(' ');
            }
        }

        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            ascii_chars,
            Style::default().fg(to_color(state.theme.palette.hex_nonprintable)),
        ));
        lines.push(Line::from(spans));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

/* render statusline at bottom with active theme preset and background worker spinner */
fn render_status_line(frame: &mut Frame, state: &AppState, area: Rect) {
    if state.mode == VimMode::Command {
        let cmd_line = Line::from(vec![
            Span::styled(":", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&state.command_buffer, Style::default().fg(Color::White)),
        ]);
        frame.render_widget(Paragraph::new(cmd_line), area);
        return;
    }

    if state.mode == VimMode::Search {
        let search_line = Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&state.search_buffer, Style::default().fg(Color::White)),
        ]);
        frame.render_widget(Paragraph::new(search_line), area);
        return;
    }

    let mode_color = match state.mode {
        VimMode::Normal => Color::Blue,
        VimMode::FieldEdit | VimMode::AsmPatch | VimMode::StringEdit | VimMode::HookEdit => Color::Yellow,
        _ => Color::Green,
    };

    let filename = state
        .elf
        .filepath
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("binary");

    let status_color = if state.is_error_message { Color::Red } else { Color::Green };

    let spinner_span = if let Some(ref task) = state.bg_task_status {
        const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame_char = SPINNER_FRAMES[state.bg_task_spinner % SPINNER_FRAMES.len()];
        Span::styled(
            format!(" | {} {} ", frame_char, task),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    let status_line = Line::from(vec![
        Span::styled(format!(" {} ", state.mode.badge_name()), Style::default().fg(Color::Black).bg(mode_color).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("[{}]", state.theme.preset.name()), Style::default().fg(to_color(state.theme.palette.border_active))),
        Span::raw(" "),
        Span::styled(filename, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled(format!("Off: 0x{:06x}", state.cursor_file_offset), Style::default().fg(Color::Cyan)),
        Span::raw(" | "),
        Span::styled(format!("VA: 0x{:08x}", state.cursor_va), Style::default().fg(Color::LightGreen)),
        spinner_span,
        Span::raw(" | "),
        Span::styled(&state.status_message, Style::default().fg(status_color)),
    ]);

    frame.render_widget(Paragraph::new(status_line), area);
}

/* render XREF caller popup modal */
fn render_xref_modal(frame: &mut Frame, state: &AppState, target_va: u64, area: Rect) {
    let modal_area = centered_rect(65, 60, area);
    frame.render_widget(Clear, modal_area);

    let items = state.cached_xref_map.as_ref().and_then(|m| m.get_xrefs(target_va));

    let list_items: Vec<ListItem> = match items {
        Some(list) => list
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let is_sel = i == state.modal_cursor;
                let style = if is_sel {
                    Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(format!(
                    "[{}] <{}+0x{:x}> @ 0x{:08x}: {}",
                    x.kind.as_str(),
                    x.caller_func,
                    x.caller_offset,
                    x.source_va,
                    x.disasm
                ))
                .style(style)
            })
            .collect(),
        None => vec![ListItem::new("No incoming cross-references found for this address.").style(Style::default().fg(Color::DarkGray))],
    };

    let title = format!(" Incoming XREFs to 0x{:08x} ", target_va);
    let modal_box = List::new(list_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(title),
    );

    frame.render_widget(modal_box, modal_area);
}

/* render Security Hardening Audit modal */
fn render_audit_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let modal_area = centered_rect(70, 65, area);
    frame.render_widget(Clear, modal_area);

    let rows: Vec<Row> = state
        .security_report
        .items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_sel = i == state.modal_cursor;
            let (badge, color) = match item.status {
                MitigationStatus::Hardened => ("HARDENED", Color::Green),
                MitigationStatus::Partial => ("PARTIAL", Color::Yellow),
                MitigationStatus::Missing => ("MISSING / VULNERABLE", Color::Red),
            };

            let row_style = if is_sel {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };

            Row::new(vec![
                item.name.clone(),
                badge.to_string(),
                item.description.clone(),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(30),
        Constraint::Length(22),
        Constraint::Percentage(48),
    ];

    let header = Row::new(vec!["Mitigation", "Status", "Evaluation Details"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" ELF Security Hardening Dashboard (Press Enter to remediate) "),
        );

    frame.render_widget(table, modal_area);
}

/* render Global Fuzzy Symbol Search modal */
fn render_symbol_search_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let modal_area = centered_rect(75, 70, area);
    frame.render_widget(Clear, modal_area);

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10)])
        .split(modal_area);

    /* input search bar */
    let search_bar = Paragraph::new(format!("> {}_", state.symbol_query)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Fuzzy Symbol Search (Type to filter, Enter to jump) "),
    );
    frame.render_widget(search_bar, split[0]);

    /* filtered symbol table */
    let rows: Vec<Row> = state
        .filtered_symbols
        .iter()
        .enumerate()
        .skip(state.modal_cursor.saturating_sub(10))
        .take(15)
        .map(|(i, s)| {
            let is_sel = i == state.modal_cursor;
            let style = if is_sel {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                s.name.clone(),
                s.sym_type.clone(),
                s.binding.clone(),
                format!("0x{:08x}", s.va),
                format!("0x{:04x}", s.file_offset),
                s.section_name.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(35),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Percentage(15),
    ];

    let header = Row::new(vec!["Symbol Name", "Type", "Binding", "VA", "Offset", "Section"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Matching Symbols "));

    frame.render_widget(table, split[1]);
}

/* render Code Cave inspector modal */
fn render_caves_modal(frame: &mut Frame, state: &AppState, area: Rect) {
    let modal_area = centered_rect(70, 60, area);
    frame.render_widget(Clear, modal_area);

    let rows: Vec<Row> = state
        .caves_list
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let is_sel = i == state.modal_cursor;
            let style = if is_sel {
                Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                format!("0x{:04x}", c.file_offset),
                c.section_name.clone(),
                format!("0x{:08x}", c.va),
                format!("{} bytes", c.capacity),
                format!("0x{:02x} ({})", c.filler_byte, if c.filler_byte == 0x90 { "NOP" } else { "NULL" }),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(16),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Percentage(30),
    ];

    let header = Row::new(vec!["File Offset", "Section", "VA", "Capacity", "Filler Byte"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Code Cave Inspector (Press Enter to deploy JMP trampoline) "),
        );

    frame.render_widget(table, modal_area);
}

/* helper to compute centered floating rectangle for popups */
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
