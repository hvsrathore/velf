/* live process attachment and virtual memory inspection via ptrace */

use anyhow::{anyhow, Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

/* active ptrace process debugging session */
pub struct LiveSession {
    pub pid: Pid,
    pub is_attached: bool,
    pub mem_file: Option<File>,
}

impl LiveSession {
    /*
     * attach to target process by PID using ptrace.
     * Synchronizes on SIGSTOP to guarantee process is paused before inspecting memory.
     */
    pub fn attach(raw_pid: i32) -> Result<Self> {
        let pid = Pid::from_raw(raw_pid);

        /* execute PTRACE_ATTACH */
        ptrace::attach(pid)
            .with_context(|| format!("failed to attach to process with PID {}", raw_pid))?;

        /* wait for target process to pause on SIGSTOP */
        match waitpid(pid, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {}
            Ok(status) => {
                /* process stopped with another signal */
                let _ = status;
            }
            Err(e) => {
                let _ = ptrace::detach(pid, None);
                return Err(anyhow!("waitpid failed during attachment: {}", e));
            }
        }

        /* open /proc/<pid>/mem for direct virtual memory reading and writing */
        let mem_path = format!("/proc/{}/mem", raw_pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)
            .ok();

        Ok(Self {
            pid,
            is_attached: true,
            mem_file,
        })
    }

    /*
     * read a chunk of Virtual Address (VA) memory from the target process.
     * Uses /proc/<pid>/mem if available, or falls back to PTRACE_PEEKTEXT.
     */
    pub fn read_memory(&mut self, va: u64, len: usize) -> Result<Vec<u8>> {
        if let Some(ref mut file) = self.mem_file {
            file.seek(SeekFrom::Start(va))
                .with_context(|| format!("failed to seek in /proc/{}/mem to 0x{:x}", self.pid, va))?;
            let mut buf = vec![0u8; len];
            let read_bytes = file.read(&mut buf)
                .with_context(|| format!("failed to read /proc/{}/mem at 0x{:x}", self.pid, va))?;
            buf.truncate(read_bytes);
            return Ok(buf);
        }

        /* fallback: read word-by-word via PTRACE_PEEKTEXT */
        let mut result = Vec::with_capacity(len);
        let mut cur_va = va;
        while result.len() < len {
            match ptrace::read(self.pid, cur_va as *mut std::ffi::c_void) {
                Ok(word) => {
                    let word_bytes = word.to_le_bytes();
                    let to_take = (len - result.len()).min(8);
                    result.extend_from_slice(&word_bytes[..to_take]);
                    cur_va += 8;
                }
                Err(e) => {
                    return Err(anyhow!("PTRACE_PEEKTEXT failed at 0x{:x}: {}", cur_va, e));
                }
            }
        }

        Ok(result)
    }

    /*
     * write modified machine code bytes directly into target process Virtual Address (VA).
     * Returns previous bytes for undo stack restoration.
     */
    pub fn write_memory(&mut self, va: u64, new_bytes: &[u8]) -> Result<Vec<u8>> {
        let old_bytes = self.read_memory(va, new_bytes.len())?;

        if let Some(ref mut file) = self.mem_file {
            file.seek(SeekFrom::Start(va))
                .with_context(|| format!("failed to seek in /proc/{}/mem to 0x{:x}", self.pid, va))?;
            file.write_all(new_bytes)
                .with_context(|| format!("failed to write to /proc/{}/mem at 0x{:x}", self.pid, va))?;
            return Ok(old_bytes);
        }

        /* fallback: word-aligned write via PTRACE_POKETEXT */
        for (i, &b) in new_bytes.iter().enumerate() {
            let addr = (va + i as u64) as *mut std::ffi::c_void;
            let current_word = ptrace::read(self.pid, addr)
                .map_err(|e| anyhow!("failed to read word before poke at 0x{:x}: {}", va + i as u64, e))?;
            let mut word_bytes = current_word.to_le_bytes();
            word_bytes[0] = b;
            let updated_word = i64::from_le_bytes(word_bytes);
            ptrace::write(self.pid, addr, updated_word)
                .map_err(|e| anyhow!("PTRACE_POKETEXT failed at 0x{:x}: {}", va + i as u64, e))?;
        }

        Ok(old_bytes)
    }

    /* detach from target process and resume normal execution */
    pub fn detach(&mut self) -> Result<()> {
        if self.is_attached {
            ptrace::detach(self.pid, None)
                .with_context(|| format!("failed to detach from process {}", self.pid))?;
            self.is_attached = false;
        }
        Ok(())
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
