/* entry point, terminal setup, and modal keybinding event loop for velf */

use anyhow::{anyhow, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::env;
use std::io::stdout;
use std::path::PathBuf;
use std::time::Duration;
use velf::{
    arch, audit, callgraph, cfg, codecave, debug, diff,
    elf::{self, format_p_flags, format_sh_flags, ElfBinary},
    live, memmap, reloc, strings, symbols,
    ui::{self, ActiveModal, AppState, CenterView},
    vim::VimMode, xref,
};

fn main() -> Result<()> {
    /* parse command line arguments */
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage();
        return Ok(());
    }

    let target_path = PathBuf::from(&args[1]);
    if !target_path.exists() {
        eprintln!("Error: target file {:?} does not exist", target_path);
        std::process::exit(1);
    }

    /* load and parse ELF binary */
    let elf = ElfBinary::load_from_file(&target_path)
        .map_err(|e| anyhow!("failed to load ELF binary from {:?}: {}", target_path, e))?;

    /* initialize crossterm alternate screen and raw terminal mode */
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    /* construct application state */
    let mut state = AppState::new(elf);

    /* run interactive event loop */
    let res = run_app(&mut terminal, &mut state);

    /* restore terminal to normal mode */
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("velf terminated with error: {:?}", err);
    }

    Ok(())
}

/* print CLI help instructions */
fn print_usage() {
    println!(
        r#"velf - Vim-like ELF Binary Editor & Inspector

USAGE:
    velf <ELF_BINARY_PATH>

MODES & KEYBINDINGS:
    NORMAL Mode:
        h, j, k, l      Pan viewport and navigate cursor
        w, b            Cycle forward / backward across instructions or blocks
        gg, G           Jump to top / jump to bottom of active view
        cc              Patch instruction (SHF_EXECINSTR) or edit field at cursor
        ciw             Edit word / field under cursor
        gd              Go to Definition: resolve branch target, symbol VA, or PLT thunk
        Ctrl-o          Jump backward along JumpStack history
        Ctrl-i          Jump forward along JumpStack history
        u               Undo machine code patch or header edit
        Ctrl-r          Redo reverted patch
        Ctrl-a, Ctrl-x  Increment / decrement integer or toggle bitflags in headers
        gf, :cfg        Toggle 2D Basic-Block Control-Flow Graph (CFG) view
        gr, :xrefs      Open incoming Cross-Reference (XREF) caller popup modal
        gs, :symbols    Open global Fuzzy Symbol Search modal
        ga, :audit      Open ELF Security Hardening Audit dashboard
        gm, :map        Switch to Visual Memory Map and Shannon entropy timeline
        gc, :callgraph  Switch to Inter-Procedural Call Graph tree view
        gp              Switch to Live Process Debugger (via ptrace)
        ]c, [c          Jump to next / previous diff chunk in hex diff view
        Tab             Cycle focus across Sidebar [1], Center [2], and Hex [3] panes
        :               Enter COMMAND mode (:q, :w, :sym, :sec, :diff, :attach)
        /               Enter live substring search / filter prompt
        Esc             Return to NORMAL mode or dismiss open modals
"#
    );
}

/* primary application event loop decoupled at ~60 FPS with batched keystrokes */
fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    state: &mut AppState,
) -> Result<()> {
    let frame_budget = Duration::from_millis(16); /* ~60 FPS rendering cap */
    let mut last_render = std::time::Instant::now();
    let mut dirty = true;

    loop {
        /* increment background spinner frame if a task is running */
        if state.bg_task_status.is_some() {
            state.bg_task_spinner = state.bg_task_spinner.wrapping_add(1);
            dirty = true;
        }

        /* only trigger ratatui redraw pass if state is dirty or frame budget elapsed */
        if dirty || last_render.elapsed() >= frame_budget {
            terminal.draw(|f| ui::render_ui(f, state))?;
            last_render = std::time::Instant::now();
            dirty = false;
        }

        /* compute remaining time slice before next frame */
        let elapsed = last_render.elapsed();
        let timeout = frame_budget.saturating_sub(elapsed);

        if event::poll(timeout)? {
            let mut key_batch = Vec::new();

            /* batch rapid keystrokes before triggering redraw pass */
            while event::poll(Duration::from_millis(0))? {
                match event::read()? {
                    Event::Key(key) => {
                        if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat {
                            key_batch.push(key);
                        }
                    }
                    Event::Resize(_, _) => {
                        dirty = true;
                    }
                    _ => {}
                }
            }

            for key in key_batch {
                let should_quit = dispatch_key_event(state, key.code, key.modifiers)?;
                if should_quit {
                    return Ok(());
                }
                dirty = true;
            }
        }
    }
}

/* dispatch key event according to active Vim mode */
fn dispatch_key_event(
    state: &mut AppState,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Result<bool> {
    match state.mode {
        VimMode::Normal => handle_normal_mode(state, code, modifiers),
        VimMode::AsmPatch => {
            handle_asm_patch_mode(state, code)?;
            Ok(false)
        }
        VimMode::FieldEdit => {
            handle_field_edit_mode(state, code)?;
            Ok(false)
        }
        VimMode::StringEdit => {
            handle_string_edit_mode(state, code)?;
            Ok(false)
        }
        VimMode::HookEdit => {
            handle_hook_edit_mode(state, code)?;
            Ok(false)
        }
        VimMode::Command => handle_command_mode(state, code),
        VimMode::Search => {
            handle_search_mode(state, code)?;
            Ok(false)
        }
    }
}

/* handle key inputs in NORMAL mode */
fn handle_normal_mode(
    state: &mut AppState,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Result<bool> {
    /* check for open modal overlays first */
    if state.modal != ActiveModal::None {
        match code {
            KeyCode::Esc => {
                state.modal = ActiveModal::None;
                state.set_status("Modal closed", false);
                return Ok(false);
            }
            KeyCode::Char('j') | KeyCode::Down => {
                state.modal_cursor = state.modal_cursor.saturating_add(1);
                return Ok(false);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                state.modal_cursor = state.modal_cursor.saturating_sub(1);
                return Ok(false);
            }
            KeyCode::Enter => {
                handle_modal_confirm(state);
                return Ok(false);
            }
            _ => {
                if state.modal == ActiveModal::SymbolSearch {
                    if let KeyCode::Char(c) = code {
                        state.symbol_query.push(c);
                        let sym_index = symbols::SymbolIndex::build(&state.elf);
                        state.filtered_symbols = sym_index.search(&state.symbol_query).into_iter().cloned().collect();
                        state.modal_cursor = 0;
                        return Ok(false);
                    } else if code == KeyCode::Backspace {
                        state.symbol_query.pop();
                        let sym_index = symbols::SymbolIndex::build(&state.elf);
                        state.filtered_symbols = sym_index.search(&state.symbol_query).into_iter().cloned().collect();
                        state.modal_cursor = 0;
                        return Ok(false);
                    }
                }
            }
        }
    }

    /* check pending non-blocking chord */
    if let Some(chord) = state.pending_chord.take() {
        match chord {
            'g' => match code {
                KeyCode::Char('d') => {
                    handle_go_to_definition(state)?;
                    return Ok(false);
                }
                KeyCode::Char('f') => {
                    toggle_cfg_view(state);
                    return Ok(false);
                }
                KeyCode::Char('r') => {
                    open_xref_modal_at_cursor(state);
                    return Ok(false);
                }
                KeyCode::Char('s') => {
                    open_symbol_search_modal(state);
                    return Ok(false);
                }
                KeyCode::Char('a') => {
                    open_audit_dashboard(state);
                    return Ok(false);
                }
                KeyCode::Char('m') => {
                    switch_to_memmap_view(state);
                    return Ok(false);
                }
                KeyCode::Char('c') => {
                    switch_to_callgraph_view(state);
                    return Ok(false);
                }
                KeyCode::Char('p') => {
                    switch_to_live_debug_view(state);
                    return Ok(false);
                }
                KeyCode::Char('t') => {
                    state.theme = state.theme.cycle_next();
                    state.set_status(&format!("Theme: {}", state.theme.preset.name()), false);
                    return Ok(false);
                }
                KeyCode::Char('g') => {
                    state.center_cursor_index = 0;
                    state.center_scroll_offset = 0;
                    state.cursor_file_offset = 0;
                    state.cursor_va = state.elf.offset_to_va(0).unwrap_or(0);
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                    state.set_status("Top of file", false);
                    return Ok(false);
                }
                _ => {}
            },
            'c' => match code {
                KeyCode::Char('c') => {
                    handle_edit_trigger(state)?;
                    return Ok(false);
                }
                KeyCode::Char('i') => {
                    state.pending_chord = Some('i');
                    state.set_status("ci...", false);
                    return Ok(false);
                }
                _ => {}
            },
            'i' => match code {
                KeyCode::Char('w') => {
                    handle_edit_trigger(state)?;
                    return Ok(false);
                }
                _ => {}
            },
            ']' => match code {
                KeyCode::Char('c') => {
                    let chunk_info = if let Some(ref mut d) = state.diff {
                        let total = d.chunks.len();
                        d.next_chunk().map(|c| (c.offset_a, c.chunk_index + 1, total))
                    } else {
                        None
                    };
                    if let Some((offset_a, cur, total)) = chunk_info {
                        state.cursor_file_offset = offset_a;
                        state.sync_hex_scroll();
                        state.update_disassembly_cache();
                        state.set_status(&format!("Diff chunk {}/{}", cur, total), false);
                    }
                    return Ok(false);
                }
                _ => {}
            },
            '[' => match code {
                KeyCode::Char('c') => {
                    let chunk_info = if let Some(ref mut d) = state.diff {
                        let total = d.chunks.len();
                        d.prev_chunk().map(|c| (c.offset_a, c.chunk_index + 1, total))
                    } else {
                        None
                    };
                    if let Some((offset_a, cur, total)) = chunk_info {
                        state.cursor_file_offset = offset_a;
                        state.sync_hex_scroll();
                        state.update_disassembly_cache();
                        state.set_status(&format!("Diff chunk {}/{}", cur, total), false);
                    }
                    return Ok(false);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /* handle control key combinations */
    if modifiers.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Char('o') => {
                /* pop location backward from jump stack */
                if let Some((off, va)) = state.jump_stack.pop_back((state.cursor_file_offset, state.cursor_va)) {
                    state.cursor_file_offset = off;
                    state.cursor_va = va;
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                    state.set_status(&format!("Jumped back to 0x{:08x}", va), false);
                } else {
                    state.set_status("JumpStack history is empty", true);
                }
                return Ok(false);
            }
            KeyCode::Char('i') => {
                /* navigate forward along jump history tree */
                if let Some((off, va)) = state.jump_stack.pop_forward((state.cursor_file_offset, state.cursor_va)) {
                    state.cursor_file_offset = off;
                    state.cursor_va = va;
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                    state.set_status(&format!("Jumped forward to 0x{:08x}", va), false);
                } else {
                    state.set_status("No forward entries in JumpStack", true);
                }
                return Ok(false);
            }
            KeyCode::Char('r') => {
                /* redo reverted patch */
                match state.undo_stack.redo(&mut state.elf) {
                    Ok(Some(off)) => {
                        state.cursor_file_offset = off;
                        state.cursor_va = state.elf.offset_to_va(off).unwrap_or(0);
                        state.update_disassembly_cache();
                        state.sync_hex_scroll();
                        state.set_status("Redo: reapplied patch", false);
                    }
                    Ok(None) => state.set_status("Already at newest change", false),
                    Err(e) => state.set_status(&format!("Redo failed: {}", e), true),
                }
                return Ok(false);
            }
            KeyCode::Char('a') => {
                /* quick bitflag or integer increment in header inspector */
                if state.center_view == CenterView::Headers && state.center_cursor_index < state.elf.fields.len() {
                    let (file_offset, width, current_val) = {
                        let f = &state.elf.fields[state.center_cursor_index];
                        (f.file_offset, f.width, f.current_value)
                    };
                    let new_val = current_val.wrapping_add(1);
                    if let Ok((old_b, new_b)) = state.elf.write_field_value(file_offset, width, new_val) {
                        state.undo_stack.push_single(file_offset, old_b, new_b);
                        let _ = state.elf.reparse();
                        state.set_status("Incremented field value", false);
                    }
                }
                return Ok(false);
            }
            KeyCode::Char('x') => {
                /* quick bitflag or integer decrement in header inspector */
                if state.center_view == CenterView::Headers && state.center_cursor_index < state.elf.fields.len() {
                    let (file_offset, width, current_val) = {
                        let f = &state.elf.fields[state.center_cursor_index];
                        (f.file_offset, f.width, f.current_value)
                    };
                    let new_val = current_val.wrapping_sub(1);
                    if let Ok((old_b, new_b)) = state.elf.write_field_value(file_offset, width, new_val) {
                        state.undo_stack.push_single(file_offset, old_b, new_b);
                        let _ = state.elf.reparse();
                        state.set_status("Decremented field value", false);
                    }
                }
                return Ok(false);
            }
            _ => {}
        }
    }

    /* standard normal mode key commands */
    match code {
        KeyCode::Char(':') => {
            state.mode = VimMode::Command;
            state.command_buffer.clear();
        }
        KeyCode::Char('/') => {
            state.mode = VimMode::Search;
            state.search_buffer.clear();
        }
        KeyCode::Char('u') => {
            /* undo most recent machine code or header patch */
            match state.undo_stack.undo(&mut state.elf) {
                Ok(Some(off)) => {
                    state.cursor_file_offset = off;
                    state.cursor_va = state.elf.offset_to_va(off).unwrap_or(0);
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                    state.set_status("Undo: reverted patch", false);
                }
                Ok(None) => state.set_status("Already at oldest change", false),
                Err(e) => state.set_status(&format!("Undo failed: {}", e), true),
            }
        }
        KeyCode::Tab => {
            /* cycle active pane: Sidebar -> Center -> Hex */
            state.active_pane = (state.active_pane + 1) % 3;
        }
        KeyCode::BackTab => {
            state.active_pane = (state.active_pane + 2) % 3;
        }

        /* navigation motions: h, j, k, l */
        KeyCode::Char('h') | KeyCode::Left => {
            if state.center_view == CenterView::Cfg {
                state.cfg_scroll_x = (state.cfg_scroll_x - 4).max(0);
            } else if state.center_view == CenterView::CallGraph {
                state.cg_scroll_x = (state.cg_scroll_x - 4).max(0);
            } else {
                state.cursor_file_offset = state.cursor_file_offset.saturating_sub(1);
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            }
        }
        KeyCode::Char('l') | KeyCode::Right => {
            if state.center_view == CenterView::Cfg {
                state.cfg_scroll_x += 4;
            } else if state.center_view == CenterView::CallGraph {
                state.cg_scroll_x += 4;
            } else if state.cursor_file_offset + 1 < state.elf.bytes.len() {
                state.cursor_file_offset += 1;
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            }
        }
        KeyCode::Char('j') | KeyCode::Down => {
            handle_down_navigation(state);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            handle_up_navigation(state);
        }
        KeyCode::Char('w') => {
            /* advance forward to next instruction or 4 bytes in O(1) */
            if state.center_view == CenterView::Disassembly {
                let cur_off = state.cursor_file_offset;
                let mut target_off = cur_off;
                for _ in 0..4 {
                    if let Some(next) = state.instruction_cache.next_offset(target_off) {
                        target_off = next;
                    } else {
                        target_off += 4;
                        break;
                    }
                }
                state.cursor_file_offset = target_off.min(state.elf.bytes.len().saturating_sub(1));
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            } else {
                state.cursor_file_offset = (state.cursor_file_offset + 4).min(state.elf.bytes.len().saturating_sub(1));
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.sync_hex_scroll();
            }
        }
        KeyCode::Char('b') => {
            /* regress backward to prior instruction or 4 bytes in O(1) */
            if state.center_view == CenterView::Disassembly {
                let cur_off = state.cursor_file_offset;
                let mut target_off = cur_off;
                for _ in 0..4 {
                    if let Some(prev) = state.instruction_cache.prev_offset(target_off) {
                        target_off = prev;
                    } else {
                        target_off = target_off.saturating_sub(4);
                        break;
                    }
                }
                state.cursor_file_offset = target_off;
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            } else {
                state.cursor_file_offset = state.cursor_file_offset.saturating_sub(4);
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.sync_hex_scroll();
            }
        }

        /* non-blocking chord initiators */
        KeyCode::Char('g') => {
            state.pending_chord = Some('g');
            state.set_status("g...", false);
        }
        KeyCode::Char('c') => {
            state.pending_chord = Some('c');
            state.set_status("c...", false);
        }
        KeyCode::Char(']') => {
            state.pending_chord = Some(']');
        }
        KeyCode::Char('[') => {
            state.pending_chord = Some('[');
        }

        KeyCode::Char('G') => {
            /* jump to bottom */
            if !state.elf.bytes.is_empty() {
                state.cursor_file_offset = state.elf.bytes.len().saturating_sub(1);
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(0);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            }
        }

        _ => {}
    }

    Ok(false)
}

/* handle vertical downward cursor navigation */
fn handle_down_navigation(state: &mut AppState) {
    if state.active_pane == 0 {
        if state.sidebar_index + 1 < state.elf.sections.len() {
            state.sidebar_index += 1;
            let sec = &state.elf.sections[state.sidebar_index];
            state.cursor_file_offset = sec.sh_offset as usize;
            state.cursor_va = sec.sh_addr;
            state.update_disassembly_cache();
            state.sync_hex_scroll();
        }
    } else if state.active_pane == 1 {
        match state.center_view {
            CenterView::Cfg => {
                state.cfg_scroll_y += 2;
            }
            CenterView::CallGraph => {
                state.cg_scroll_y += 2;
            }
            CenterView::Headers => {
                if state.center_cursor_index + 1 < state.elf.fields.len() {
                    state.center_cursor_index += 1;
                    if state.center_cursor_index >= state.center_scroll_offset + 20 {
                        state.center_scroll_offset += 1;
                    }
                    let field = &state.elf.fields[state.center_cursor_index];
                    state.cursor_file_offset = field.file_offset;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Strings => {
                if state.center_cursor_index + 1 < state.strings_list.len() {
                    state.center_cursor_index += 1;
                    if state.center_cursor_index >= state.center_scroll_offset + 20 {
                        state.center_scroll_offset += 1;
                    }
                    let s = &state.strings_list[state.center_cursor_index];
                    state.cursor_file_offset = s.file_offset;
                    state.cursor_va = s.va;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Reloc => {
                if state.center_cursor_index + 1 < state.reloc_list.len() {
                    state.center_cursor_index += 1;
                    let r = &state.reloc_list[state.center_cursor_index];
                    state.cursor_file_offset = r.file_offset;
                    state.cursor_va = r.r_offset;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Disassembly => {
                /* step to next instruction in O(1) time using InstructionCache */
                let cur_off = state.cursor_file_offset;
                let next_off = if let Some(off) = state.instruction_cache.next_offset(cur_off) {
                    off
                } else {
                    let cur_va = state.cursor_va;
                    if let Some(instr) = state.instruction_cache.get_or_decode(&state.elf.bytes, cur_off, cur_va) {
                        cur_off + instr.len
                    } else {
                        (cur_off + 4).min(state.elf.bytes.len().saturating_sub(1))
                    }
                };

                if next_off < state.elf.bytes.len() {
                    state.cursor_file_offset = next_off;
                    state.cursor_va = state.elf.offset_to_va(next_off).unwrap_or(state.cursor_va + (next_off - cur_off) as u64);
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                }
            }
            _ => {
                state.cursor_file_offset = (state.cursor_file_offset + 16).min(state.elf.bytes.len().saturating_sub(1));
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.sync_hex_scroll();
            }
        }
    } else {
        /* step hex pane 16 bytes forward */
        state.cursor_file_offset = (state.cursor_file_offset + 16).min(state.elf.bytes.len().saturating_sub(1));
        state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
        state.update_disassembly_cache();
        state.sync_hex_scroll();
    }
}

/* handle vertical upward cursor navigation */
fn handle_up_navigation(state: &mut AppState) {
    if state.active_pane == 0 {
        if state.sidebar_index > 0 {
            state.sidebar_index -= 1;
            let sec = &state.elf.sections[state.sidebar_index];
            state.cursor_file_offset = sec.sh_offset as usize;
            state.cursor_va = sec.sh_addr;
            state.update_disassembly_cache();
            state.sync_hex_scroll();
        }
    } else if state.active_pane == 1 {
        match state.center_view {
            CenterView::Cfg => {
                state.cfg_scroll_y = (state.cfg_scroll_y - 2).max(0);
            }
            CenterView::CallGraph => {
                state.cg_scroll_y = (state.cg_scroll_y - 2).max(0);
            }
            CenterView::Headers => {
                if state.center_cursor_index > 0 {
                    state.center_cursor_index -= 1;
                    if state.center_cursor_index < state.center_scroll_offset {
                        state.center_scroll_offset = state.center_cursor_index;
                    }
                    let field = &state.elf.fields[state.center_cursor_index];
                    state.cursor_file_offset = field.file_offset;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Strings => {
                if state.center_cursor_index > 0 {
                    state.center_cursor_index -= 1;
                    if state.center_cursor_index < state.center_scroll_offset {
                        state.center_scroll_offset = state.center_cursor_index;
                    }
                    let s = &state.strings_list[state.center_cursor_index];
                    state.cursor_file_offset = s.file_offset;
                    state.cursor_va = s.va;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Reloc => {
                if state.center_cursor_index > 0 {
                    state.center_cursor_index -= 1;
                    let r = &state.reloc_list[state.center_cursor_index];
                    state.cursor_file_offset = r.file_offset;
                    state.cursor_va = r.r_offset;
                    state.sync_hex_scroll();
                }
            }
            CenterView::Disassembly => {
                /* step to previous instruction in O(1) time using InstructionCache */
                let cur_off = state.cursor_file_offset;
                let prev_off = if let Some(off) = state.instruction_cache.prev_offset(cur_off) {
                    off
                } else {
                    cur_off.saturating_sub(4)
                };

                state.cursor_file_offset = prev_off;
                state.cursor_va = state.elf.offset_to_va(prev_off).unwrap_or(0);
                state.update_disassembly_cache();
                state.sync_hex_scroll();
            }
            _ => {
                state.cursor_file_offset = state.cursor_file_offset.saturating_sub(16);
                state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
                state.sync_hex_scroll();
            }
        }
    } else {
        state.cursor_file_offset = state.cursor_file_offset.saturating_sub(16);
        state.cursor_va = state.elf.offset_to_va(state.cursor_file_offset).unwrap_or(state.cursor_va);
        state.update_disassembly_cache();
        state.sync_hex_scroll();
    }
}

/*
 * resolve target under cursor and push onto JumpStack ('gd').
 * Disassembly: resolves branch target (CALL, JMP, Jcc) or RIP-relative displacement pointing to .got.plt.
 * Symbols: resolves st_value.
 * Relocations: resolves target address.
 * Strings: jumps to raw bytes.
 */
fn handle_go_to_definition(state: &mut AppState) -> Result<()> {
    let mut resolved_va = None;

    match state.center_view {
        CenterView::Disassembly => {
            if let Some(target_instr) = state.cached_disasm.iter().find(|i| i.file_offset <= state.cursor_file_offset && state.cursor_file_offset < i.file_offset + i.len) {
                if let Some(t) = target_instr.near_branch_target() {
                    resolved_va = Some(t);
                } else if target_instr.is_ip_rel_memory() {
                    resolved_va = target_instr.ip_rel_memory_address();
                }
            }
        }
        CenterView::Strings => {
            if let Some(s) = state.strings_list.get(state.center_cursor_index) {
                resolved_va = Some(s.va);
            }
        }
        CenterView::Reloc => {
            if let Some(r) = state.reloc_list.get(state.center_cursor_index) {
                resolved_va = Some(r.current_target_va);
            }
        }
        _ => {}
    }

    if let Some(va) = resolved_va {
        if let Some(off) = state.elf.va_to_offset(va) {
            state.jump_stack.push(state.cursor_file_offset, state.cursor_va);
            state.cursor_file_offset = off;
            state.cursor_va = va;
            state.update_disassembly_cache();
            state.sync_hex_scroll();
            state.set_status(&format!("Jumped (gd) to 0x{:08x} (offset 0x{:04x})", va, off), false);
            return Ok(());
        }
    }

    state.set_status("Could not resolve branch or symbol target under cursor", true);
    Ok(())
}

/* trigger inline edit prompt based on active view */
fn handle_edit_trigger(state: &mut AppState) -> Result<()> {
    match state.center_view {
        CenterView::Disassembly | CenterView::Cfg => {
            state.mode = VimMode::AsmPatch;
            state.input_buffer.clear();
            state.set_status("Enter assembly mnemonic (e.g. 'nop', 'ret', 'mov eax, 1', 'xor rdi, rdi')", false);
        }
        CenterView::Headers => {
            state.mode = VimMode::FieldEdit;
            if let Some(f) = state.elf.fields.get(state.center_cursor_index) {
                state.input_buffer = if f.is_flags && f.field_name == "p_flags" {
                    format_p_flags(f.current_value as u32)
                } else if f.is_flags && f.field_name == "sh_flags" {
                    format_sh_flags(f.current_value)
                } else {
                    format!("0x{:x}", f.current_value)
                };
            }
            state.set_status("Edit field value (supports hex, decimal, or bitflag expressions)", false);
        }
        CenterView::Strings => {
            state.mode = VimMode::StringEdit;
            if let Some(s) = state.strings_list.get(state.center_cursor_index) {
                state.input_buffer = strings::escape_string(&s.content);
            }
            state.set_status("Edit string literal (in-place null-termination enforced)", false);
        }
        CenterView::Reloc => {
            state.mode = VimMode::HookEdit;
            if let Some(r) = state.reloc_list.get(state.center_cursor_index) {
                state.input_buffer = format!("0x{:x}", r.current_target_va);
            }
            state.set_status("Enter target Virtual Address for function hook redirection", false);
        }
        _ => {}
    }
    Ok(())
}

/* handle ASM_PATCH mode inline typing and confirmation */
fn handle_asm_patch_mode(state: &mut AppState, code: KeyCode) -> Result<()> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.input_buffer.clear();
            state.set_status("ASM_PATCH aborted", false);
        }
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
        }
        KeyCode::Enter => {
            /* execute in-place instruction patch */
            let target_va = state.cursor_va;
            let orig_len = 5; /* estimate default original size or lookup from decoded instruction */

            match arch::parse_and_encode_instruction(&state.input_buffer, target_va, orig_len) {
                Ok(new_bytes) => {
                    let old_bytes = state.elf.bytes[state.cursor_file_offset..state.cursor_file_offset + orig_len].to_vec();
                    state.elf.bytes[state.cursor_file_offset..state.cursor_file_offset + orig_len].copy_from_slice(&new_bytes);
                    state.undo_stack.push_single(state.cursor_file_offset, old_bytes, new_bytes);
                    let _ = state.elf.reparse();
                    state.update_disassembly_cache();
                    state.mode = VimMode::Normal;
                    state.set_status("Instruction patched with automatic NOP padding", false);
                }
                Err(e) => {
                    /* if patch exceeded original length, check code cave availability */
                    if state.caves_list.is_empty() {
                        state.set_status(&format!("Patch error: {}", e), true);
                    } else {
                        state.set_status(&format!("Patch too large: {}. Use :caves to deploy JMP trampoline.", e), true);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/* handle FIELD_EDIT mode inline editing */
fn handle_field_edit_mode(state: &mut AppState, code: KeyCode) -> Result<()> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.input_buffer.clear();
            state.set_status("Field edit cancelled", false);
        }
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
        }
        KeyCode::Enter => {
            if let Some(field) = state.elf.fields.get(state.center_cursor_index).cloned() {
                match elf::parse_field_input(&state.input_buffer, field.is_flags, &field.field_name) {
                    Ok(new_val) => {
                        match state.elf.write_field_value(field.file_offset, field.width, new_val) {
                            Ok((old_b, new_b)) => {
                                state.undo_stack.push_single(field.file_offset, old_b, new_b);
                                let _ = state.elf.reparse();
                                state.mode = VimMode::Normal;
                                state.set_status(&format!("Updated {} to 0x{:x}", field.field_name, new_val), false);
                            }
                            Err(e) => state.set_status(&format!("Write failed: {}", e), true),
                        }
                    }
                    Err(e) => state.set_status(&format!("Invalid field input: {}", e), true),
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/* handle STRING_EDIT mode inline editing */
fn handle_string_edit_mode(state: &mut AppState, code: KeyCode) -> Result<()> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.input_buffer.clear();
            state.set_status("String edit cancelled", false);
        }
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
        }
        KeyCode::Enter => {
            if let Some(entry) = state.strings_list.get(state.center_cursor_index).cloned() {
                match strings::prepare_string_patch(&state.input_buffer, entry.max_slot_len) {
                    Ok(new_slot_bytes) => {
                        let end = entry.file_offset + entry.max_slot_len;
                        let old_bytes = state.elf.bytes[entry.file_offset..end].to_vec();
                        state.elf.bytes[entry.file_offset..end].copy_from_slice(&new_slot_bytes);
                        state.undo_stack.push_single(entry.file_offset, old_bytes, new_slot_bytes);
                        let _ = state.elf.reparse();
                        state.mode = VimMode::Normal;
                        state.set_status("String literal successfully patched in-place", false);
                    }
                    Err(e) => state.set_status(&format!("String edit error: {}", e), true),
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/* handle HOOK_EDIT mode inline editing */
fn handle_hook_edit_mode(state: &mut AppState, code: KeyCode) -> Result<()> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.input_buffer.clear();
            state.set_status("Hook edit cancelled", false);
        }
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
        }
        KeyCode::Enter => {
            if let Some(entry) = state.reloc_list.get(state.center_cursor_index).cloned() {
                match arch::parse_number(&state.input_buffer) {
                    Ok(target_va) => {
                        match reloc::write_hook_target(&mut state.elf, entry.file_offset, target_va) {
                            Ok((old_b, new_b)) => {
                                state.undo_stack.push_single(entry.file_offset, old_b, new_b);
                                let _ = state.elf.reparse();
                                state.mode = VimMode::Normal;
                                state.set_status(&format!("Hook redirected to 0x{:08x}", target_va), false);
                            }
                            Err(e) => state.set_status(&format!("Hook redirection failed: {}", e), true),
                        }
                    }
                    Err(e) => state.set_status(&format!("Invalid target address: {}", e), true),
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/* handle COMMAND mode inputs (:q, :w, :sym, :sec, etc.) */
fn handle_command_mode(state: &mut AppState, code: KeyCode) -> Result<bool> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.command_buffer.clear();
        }
        KeyCode::Char(c) => {
            state.command_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.command_buffer.pop();
            if state.command_buffer.is_empty() {
                state.mode = VimMode::Normal;
            }
        }
        KeyCode::Enter => {
            let cmd = state.command_buffer.trim().to_string();
            state.mode = VimMode::Normal;
            state.command_buffer.clear();

            if cmd == "q" || cmd == "quit" || cmd == "q!" {
                return Ok(true); /* exit application */
            } else if cmd == "w" || cmd == "write" {
                if let Some(ref path) = state.elf.filepath {
                    state.elf.save_to_file(path)?;
                    state.set_status(&format!("Binary written to {:?}", path), false);
                } else {
                    state.set_status("No filename specified. Use :w <path>", true);
                }
            } else if let Some(path_str) = cmd.strip_prefix("w ") {
                let p = PathBuf::from(path_str.trim());
                state.elf.save_to_file(&p)?;
                state.set_status(&format!("Binary written to {:?}", p), false);
            } else if cmd == "cfg" {
                toggle_cfg_view(state);
            } else if cmd == "strings" {
                let xrefs = if let Some(ref m) = state.cached_xref_map {
                    m.clone()
                } else {
                    let m = xref::XrefMap::build_from_elf(&state.elf);
                    state.cached_xref_map = Some(m.clone());
                    m
                };
                state.strings_list = strings::scan_strings(&state.elf, &xrefs);
                state.center_view = CenterView::Strings;
                state.set_status(&format!("Loaded {} strings", state.strings_list.len()), false);
            } else if cmd == "map" {
                switch_to_memmap_view(state);
            } else if cmd == "plt" {
                state.reloc_list = reloc::parse_relocations(&state.elf);
                state.center_view = CenterView::Reloc;
                state.set_status(&format!("Loaded {} dynamic relocations", state.reloc_list.len()), false);
            } else if cmd == "caves" {
                state.caves_list = codecave::scan_code_caves(&state.elf, 16);
                state.modal = ActiveModal::CodeCaves;
                state.modal_cursor = 0;
            } else if cmd == "audit" {
                open_audit_dashboard(state);
            } else if cmd == "symbols" {
                open_symbol_search_modal(state);
            } else if cmd == "callgraph" {
                switch_to_callgraph_view(state);
            } else if cmd == "source" {
                state.show_source_lines = !state.show_source_lines;
                state.set_status(&format!("Source line annotations: {}", if state.show_source_lines { "ON" } else { "OFF" }), false);
            } else if let Some(sym_name) = cmd.strip_prefix("sym ") {
                let found_sym = state.elf.find_symbol_by_name(sym_name.trim())
                    .map(|s| (s.name.clone(), s.st_value));
                if let Some((name, va)) = found_sym {
                    if let Some(off) = state.elf.va_to_offset(va) {
                        state.jump_stack.push(state.cursor_file_offset, state.cursor_va);
                        state.cursor_file_offset = off;
                        state.cursor_va = va;
                        state.update_disassembly_cache();
                        state.sync_hex_scroll();
                        state.set_status(&format!("Jumped to symbol '{}' @ 0x{:08x}", name, va), false);
                    }
                } else {
                    state.set_status(&format!("Symbol '{}' not found", sym_name), true);
                }
            } else if let Some(sec_name) = cmd.strip_prefix("sec ") {
                let found_sec = state.elf.find_section_by_name(sec_name.trim())
                    .map(|s| (s.name.clone(), s.sh_offset as usize, s.sh_addr));
                if let Some((name, off, va)) = found_sec {
                    state.jump_stack.push(state.cursor_file_offset, state.cursor_va);
                    state.cursor_file_offset = off;
                    state.cursor_va = va;
                    state.update_disassembly_cache();
                    state.sync_hex_scroll();
                    state.set_status(&format!("Jumped to section '{}'", name), false);
                } else {
                    state.set_status(&format!("Section '{}' not found", sec_name), true);
                }
            } else if let Some(pid_str) = cmd.strip_prefix("attach ") {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    match live::LiveSession::attach(pid) {
                        Ok(session) => {
                            state.live_session = Some(session);
                            if let Ok(regs) = debug::read_cpu_registers(nix::unistd::Pid::from_raw(pid)) {
                                state.cpu_regs = Some(regs);
                            }
                            state.center_view = CenterView::LiveDebug;
                            state.set_status(&format!("Attached to process PID {}", pid), false);
                        }
                        Err(e) => state.set_status(&format!("Attach failed: {}", e), true),
                    }
                }
            } else if let Some(diff_path) = cmd.strip_prefix("diff ") {
                match diff::BinaryDiff::load_and_compare(&state.elf.bytes, diff_path.trim()) {
                    Ok(d) => {
                        state.diff = Some(d);
                        state.center_view = CenterView::Diff;
                        state.set_status("Hex diff loaded", false);
                    }
                    Err(e) => state.set_status(&format!("Diff failed: {}", e), true),
                }
            } else if let Some(theme_arg) = cmd.strip_prefix("theme ") {
                if let Some(th) = velf::theme::Theme::from_preset_name(theme_arg.trim()) {
                    state.theme = th;
                    state.set_status(&format!("Theme set to {}", state.theme.preset.name()), false);
                } else {
                    state.set_status(&format!("Unknown theme preset '{}'", theme_arg), true);
                }
            } else if cmd == "rop" {
                state.bg_task_status = Some("Scanning ROP gadgets in parallel...".to_string());
                let gadgets = velf::rop::scan_rop_gadgets_parallel(&state.elf);
                state.bg_task_status = None;
                state.set_status(&format!("Found {} ROP gadgets across executable sections", gadgets.len()), false);
            } else if cmd == "entropy" {
                state.bg_task_status = Some("Calculating parallel Shannon entropy...".to_string());
                let analysis = velf::entropy::EntropyAnalysis::compute_parallel(&state.elf.bytes, Some(state.elf.entry));
                state.bg_task_status = None;
                switch_to_memmap_view(state);
                state.set_status(&format!("Shannon Entropy: mean {:.2}, min {:.2}, max {:.2}", analysis.mean_entropy, analysis.min_entropy, analysis.max_entropy), false);
            } else {
                state.set_status(&format!("Unknown command: ':{}'", cmd), true);
            }
        }
        _ => {}
    }
    Ok(false)
}

/* handle SEARCH mode */
fn handle_search_mode(state: &mut AppState, code: KeyCode) -> Result<()> {
    match code {
        KeyCode::Esc => {
            state.mode = VimMode::Normal;
            state.search_buffer.clear();
        }
        KeyCode::Char(c) => {
            state.search_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.search_buffer.pop();
            if state.search_buffer.is_empty() {
                state.mode = VimMode::Normal;
            }
        }
        KeyCode::Enter => {
            state.mode = VimMode::Normal;
            state.set_status(&format!("Search query: '{}'", state.search_buffer), false);
        }
        _ => {}
    }
    Ok(())
}

/* handle Enter confirmation in active modal overlay */
fn handle_modal_confirm(state: &mut AppState) {
    let current_modal = state.modal.clone();
    match current_modal {
        ActiveModal::Xref(va) => {
            let target = state
                .cached_xref_map
                .as_ref()
                .and_then(|m| m.get_xrefs(va))
                .and_then(|list| list.get(state.modal_cursor).cloned());
            if let Some(entry) = target {
                state.jump_stack.push(state.cursor_file_offset, state.cursor_va);
                state.cursor_file_offset = entry.source_file_offset;
                state.cursor_va = entry.source_va;
                state.update_disassembly_cache();
                state.sync_hex_scroll();
                state.modal = ActiveModal::None;
                state.set_status(&format!("Jumped to caller @ 0x{:08x}", entry.source_va), false);
            }
        }
        ActiveModal::Audit => {
            let target = state
                .security_report
                .items
                .get(state.modal_cursor)
                .cloned();
            if let Some(item) = target {
                if let Some(off) = item.target_file_offset {
                    state.cursor_file_offset = off;
                    state.center_view = CenterView::Headers;
                    state.modal = ActiveModal::None;
                    state.set_status(&format!("Jumped to header field for {}", item.name), false);
                }
            }
        }
        ActiveModal::SymbolSearch => {
            if let Some(sym) = state.filtered_symbols.get(state.modal_cursor).cloned() {
                state.jump_stack.push(state.cursor_file_offset, state.cursor_va);
                state.cursor_file_offset = sym.file_offset;
                state.cursor_va = sym.va;
                state.update_disassembly_cache();
                state.sync_hex_scroll();
                state.modal = ActiveModal::None;
                state.set_status(&format!("Jumped to symbol '{}' @ 0x{:08x}", sym.name, sym.va), false);
            }
        }
        ActiveModal::CodeCaves => {
            state.modal = ActiveModal::None;
            state.set_status("Selected code cave for trampoline deployment", false);
        }
        ActiveModal::None => {}
    }
}

/* toggle between linear Disassembly and 2D CFG view */
fn toggle_cfg_view(state: &mut AppState) {
    if state.center_view == CenterView::Cfg {
        state.center_view = CenterView::Disassembly;
        state.set_status("Switched to linear disassembly view", false);
    } else {
        /* locate current function symbol */
        let funcs = state.elf.find_function_symbols();
        let cur_va = state.cursor_va;
        let func = funcs.iter().find(|f| cur_va >= f.st_value && cur_va < f.st_value + f.st_size)
            .or_else(|| funcs.first());

        if let Some(f) = func {
            let sec = state.elf.find_section_at_offset(state.cursor_file_offset)
                .or_else(|| state.elf.sections.iter().find(|s| s.is_executable));

            if let Some(s) = sec {
                let slice = &state.elf.bytes[s.sh_offset as usize..(s.sh_offset + s.sh_size) as usize];
                let instructions = arch::disassemble_slice(slice, s.sh_addr, s.sh_offset as usize);
                if let Some(cfg) = cfg::ControlFlowGraph::build(f, &instructions) {
                    state.cfg = Some(cfg);
                    state.cfg_selected_block_idx = 0;
                    state.cfg_selected_instr_idx = 0;
                    state.center_view = CenterView::Cfg;
                    state.set_status(&format!("CFG generated for '{}'", f.name), false);
                    return;
                }
            }
        }

        state.set_status("No executable function located under cursor for CFG", true);
    }
}

/* open incoming XREF modal */
fn open_xref_modal_at_cursor(state: &mut AppState) {
    if state.cached_xref_map.is_none() {
        state.cached_xref_map = Some(xref::XrefMap::build_from_elf(&state.elf));
    }
    state.modal = ActiveModal::Xref(state.cursor_va);
    state.modal_cursor = 0;
}

/* open fuzzy symbol search modal */
fn open_symbol_search_modal(state: &mut AppState) {
    let sym_index = symbols::SymbolIndex::build(&state.elf);
    state.symbol_query.clear();
    state.filtered_symbols = sym_index.symbols;
    state.modal = ActiveModal::SymbolSearch;
    state.modal_cursor = 0;
}

/* open security hardening audit dashboard */
fn open_audit_dashboard(state: &mut AppState) {
    state.security_report = audit::SecurityReport::scan(&state.elf);
    state.modal = ActiveModal::Audit;
    state.modal_cursor = 0;
}

/* switch to Visual Memory Map view */
fn switch_to_memmap_view(state: &mut AppState) {
    state.memory_map = memmap::MemoryMap::build(&state.elf);
    state.center_view = CenterView::MemoryMap;
    state.set_status("Switched to Visual Memory Map view", false);
}

/* switch to Inter-Procedural Call Graph view */
fn switch_to_callgraph_view(state: &mut AppState) {
    state.callgraph = Some(callgraph::CallGraph::build(&state.elf));
    state.cg_selected_node_idx = 0;
    state.center_view = CenterView::CallGraph;
    state.set_status("Call Graph generated", false);
}

/* switch to Live Process Debugger view */
fn switch_to_live_debug_view(state: &mut AppState) {
    state.center_view = CenterView::LiveDebug;
    state.set_status("Switched to Live Debugger view", false);
}
