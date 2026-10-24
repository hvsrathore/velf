/* live CPU register inspection, execution control, and INT 3 software breakpoints */

use crate::live::LiveSession;
use anyhow::{anyhow, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;

/* x86_64 CPU register snapshot extracted via ptrace */
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuRegisters {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
}

/* software breakpoint tracked at a Virtual Address (VA) */
#[derive(Debug, Clone)]
pub struct SoftwareBreakpoint {
    pub va: u64,
    pub original_byte: u8,
    pub is_enabled: bool,
}

/* manager maintaining active software breakpoints */
#[derive(Debug, Clone, Default)]
pub struct BreakpointManager {
    pub breakpoints: HashMap<u64, SoftwareBreakpoint>,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
        }
    }

    /*
     * toggle a software breakpoint at target Virtual Address (VA).
     * Injects INT 3 (0xCC) opcode trap into process memory.
     */
    pub fn toggle_breakpoint(&mut self, session: &mut LiveSession, va: u64) -> Result<bool> {
        if let Some(bp) = self.breakpoints.remove(&va) {
            /* restore original byte */
            session.write_memory(va, &[bp.original_byte])?;
            Ok(false) /* removed */
        } else {
            /* read original byte and inject 0xCC (INT 3) */
            let orig_bytes = session.read_memory(va, 1)?;
            if orig_bytes.is_empty() {
                return Err(anyhow!("failed to read byte at 0x{:x}", va));
            }
            let original_byte = orig_bytes[0];
            session.write_memory(va, &[0xcc])?;

            self.breakpoints.insert(
                va,
                SoftwareBreakpoint {
                    va,
                    original_byte,
                    is_enabled: true,
                },
            );
            Ok(true) /* added */
        }
    }
}

/*
 * extract live CPU general-purpose registers using PTRACE_GETREGS.
 */
pub fn read_cpu_registers(pid: Pid) -> Result<CpuRegisters> {
    let regs = ptrace::getregs(pid)
        .map_err(|e| anyhow!("PTRACE_GETREGS failed: {}", e))?;

    Ok(CpuRegisters {
        rip: regs.rip,
        rsp: regs.rsp,
        rbp: regs.rbp,
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        rflags: regs.eflags,
    })
}

/*
 * write modified CPU register value using PTRACE_SETREGS.
 */
pub fn write_cpu_register(pid: Pid, reg_name: &str, new_value: u64) -> Result<()> {
    let mut regs = ptrace::getregs(pid)
        .map_err(|e| anyhow!("PTRACE_GETREGS failed: {}", e))?;

    match reg_name.to_ascii_lowercase().as_str() {
        "rip" => regs.rip = new_value,
        "rsp" => regs.rsp = new_value,
        "rbp" => regs.rbp = new_value,
        "rax" => regs.rax = new_value,
        "rbx" => regs.rbx = new_value,
        "rcx" => regs.rcx = new_value,
        "rdx" => regs.rdx = new_value,
        "rsi" => regs.rsi = new_value,
        "rdi" => regs.rdi = new_value,
        "r8" => regs.r8 = new_value,
        "r9" => regs.r9 = new_value,
        "r10" => regs.r10 = new_value,
        "r11" => regs.r11 = new_value,
        "r12" => regs.r12 = new_value,
        "r13" => regs.r13 = new_value,
        "r14" => regs.r14 = new_value,
        "r15" => regs.r15 = new_value,
        "rflags" => regs.eflags = new_value,
        _ => return Err(anyhow!("unknown register name: {}", reg_name)),
    }

    ptrace::setregs(pid, regs)
        .map_err(|e| anyhow!("PTRACE_SETREGS failed: {}", e))
}

/*
 * continue process execution using PTRACE_CONT and handle breakpoint traps.
 * If a breakpoint is hit, intercepts SIGTRAP, rewinds RIP by 1 byte,
 * and restores original machine code.
 */
pub fn continue_execution(
    session: &mut LiveSession,
    bp_mgr: &mut BreakpointManager,
) -> Result<Option<u64>> {
    let pid = session.pid;
    ptrace::cont(pid, None)
        .map_err(|e| anyhow!("PTRACE_CONT failed: {}", e))?;

    match waitpid(pid, None)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {
            /* intercepted breakpoint trap */
            let mut regs = ptrace::getregs(pid)?;
            let trap_va = regs.rip.saturating_sub(1);

            if let Some(bp) = bp_mgr.breakpoints.get(&trap_va) {
                /* restore original opcode byte */
                session.write_memory(trap_va, &[bp.original_byte])?;

                /* rewind RIP by 1 byte to re-execute original instruction */
                regs.rip = trap_va;
                ptrace::setregs(pid, regs)?;

                return Ok(Some(trap_va));
            }

            Ok(Some(regs.rip))
        }
        WaitStatus::Exited(_, exit_code) => {
            session.is_attached = false;
            Err(anyhow!("target process exited with code {}", exit_code))
        }
        _ => Ok(None),
    }
}

/*
 * execute a single instruction step using PTRACE_SINGLESTEP.
 */
pub fn single_step(pid: Pid) -> Result<u64> {
    ptrace::step(pid, None)
        .map_err(|e| anyhow!("PTRACE_SINGLESTEP failed: {}", e))?;

    match waitpid(pid, None)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => {
            let regs = ptrace::getregs(pid)?;
            Ok(regs.rip)
        }
        WaitStatus::Exited(_, code) => Err(anyhow!("process exited with code {}", code)),
        _ => {
            let regs = ptrace::getregs(pid)?;
            Ok(regs.rip)
        }
    }
}
