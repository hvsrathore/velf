/* side-by-side binary hex diffing engine and chunk navigator */

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/* discrete chunk of differing bytes between two binary buffers */
#[derive(Debug, Clone)]
pub struct DiffChunk {
    pub chunk_index: usize,
    pub offset_a: usize,
    pub offset_b: usize,
    pub length: usize,
    pub bytes_a: Vec<u8>,
    pub bytes_b: Vec<u8>,
}

/* binary comparison session state */
#[derive(Debug, Clone)]
pub struct BinaryDiff {
    pub comparison_path: PathBuf,
    pub bytes_b: Vec<u8>,
    pub chunks: Vec<DiffChunk>,
    pub current_chunk_idx: usize,
}

impl BinaryDiff {
    /* load comparison binary from disk and compute byte-level differences */
    pub fn load_and_compare<P: AsRef<Path>>(
        primary_bytes: &[u8],
        compare_path: P,
    ) -> Result<Self> {
        let path_buf = compare_path.as_ref().to_path_buf();
        let bytes_b = fs::read(&path_buf)
            .with_context(|| format!("failed to read diff file {:?}", path_buf))?;

        let chunks = compute_diff_chunks(primary_bytes, &bytes_b);

        Ok(Self {
            comparison_path: path_buf,
            bytes_b,
            chunks,
            current_chunk_idx: 0,
        })
    }

    /* jump to next difference chunk (Vim ']c') */
    pub fn next_chunk(&mut self) -> Option<&DiffChunk> {
        if self.chunks.is_empty() {
            return None;
        }
        if self.current_chunk_idx + 1 < self.chunks.len() {
            self.current_chunk_idx += 1;
        }
        self.chunks.get(self.current_chunk_idx)
    }

    /* jump to previous difference chunk (Vim '[c') */
    pub fn prev_chunk(&mut self) -> Option<&DiffChunk> {
        if self.chunks.is_empty() {
            return None;
        }
        if self.current_chunk_idx > 0 {
            self.current_chunk_idx -= 1;
        }
        self.chunks.get(self.current_chunk_idx)
    }

    /* get currently focused chunk */
    pub fn current_chunk(&self) -> Option<&DiffChunk> {
        self.chunks.get(self.current_chunk_idx)
    }
}

/*
 * compare two byte slices using a sliding window algorithm.
 * Groups contiguous differing bytes into discrete DiffChunks.
 */
pub fn compute_diff_chunks(a: &[u8], b: &[u8]) -> Vec<DiffChunk> {
    let mut chunks = Vec::new();
    let max_len = a.len().max(b.len());
    let mut idx = 0;
    let mut chunk_id = 0;

    while idx < max_len {
        let byte_a = a.get(idx).copied();
        let byte_b = b.get(idx).copied();

        if byte_a != byte_b {
            let start = idx;
            let mut diff_a = Vec::new();
            let mut diff_b = Vec::new();

            while idx < max_len {
                let cur_a = a.get(idx).copied();
                let cur_b = b.get(idx).copied();
                if cur_a == cur_b {
                    /* check if next 4 bytes are identical to end the chunk */
                    let mut lookahead_match = true;
                    for look in 1..=4 {
                        if idx + look < max_len && a.get(idx + look) != b.get(idx + look) {
                            lookahead_match = false;
                            break;
                        }
                    }
                    if lookahead_match {
                        break;
                    }
                }

                if let Some(val) = cur_a {
                    diff_a.push(val);
                }
                if let Some(val) = cur_b {
                    diff_b.push(val);
                }
                idx += 1;
            }

            let len = idx - start;
            chunks.push(DiffChunk {
                chunk_index: chunk_id,
                offset_a: start,
                offset_b: start,
                length: len,
                bytes_a: diff_a,
                bytes_b: diff_b,
            });
            chunk_id += 1;
        } else {
            idx += 1;
        }
    }

    chunks
}
