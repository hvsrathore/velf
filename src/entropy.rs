/* parallel Shannon entropy sliding-window and block calculation engine */

use rayon::prelude::*;

/* 256-byte analysis block size for Shannon entropy calculations */
pub const ENTROPY_BLOCK_SIZE: usize = 256;

/* single calculated entropy block along file offset and optional virtual memory address */
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyBlock {
    pub file_offset: usize,
    pub va: Option<u64>,
    pub size: usize,
    pub entropy: f64,
}

/* comprehensive Shannon entropy report across binary regions */
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    pub blocks: Vec<EntropyBlock>,
    pub overall_entropy: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub mean_entropy: f64,
}

impl EntropyAnalysis {
    /*
     * calculate Shannon entropy across 256-byte blocks in parallel using Rayon par_chunks().
     * Accurately identifies encrypted/compressed payloads, padding gaps, and code sections.
     */
    pub fn compute_parallel(bytes: &[u8], base_va: Option<u64>) -> Self {
        if bytes.is_empty() {
            return Self {
                blocks: Vec::new(),
                overall_entropy: 0.0,
                min_entropy: 0.0,
                max_entropy: 0.0,
                mean_entropy: 0.0,
            };
        }

        let overall = calculate_entropy(bytes);

        /* parallelize sliding-window block calculations across CPU cores */
        let blocks: Vec<EntropyBlock> = bytes
            .par_chunks(ENTROPY_BLOCK_SIZE)
            .enumerate()
            .map(|(chunk_idx, chunk)| {
                let offset = chunk_idx * ENTROPY_BLOCK_SIZE;
                let va = base_va.map(|b| b + offset as u64);
                let ent = calculate_entropy(chunk);
                EntropyBlock {
                    file_offset: offset,
                    va,
                    size: chunk.len(),
                    entropy: ent,
                }
            })
            .collect();

        let mut min_e = 8.0f64;
        let mut max_e = 0.0f64;
        let mut sum_e = 0.0f64;

        for b in &blocks {
            if b.entropy < min_e {
                min_e = b.entropy;
            }
            if b.entropy > max_e {
                max_e = b.entropy;
            }
            sum_e += b.entropy;
        }

        let mean_e = if !blocks.is_empty() {
            sum_e / blocks.len() as f64
        } else {
            0.0
        };

        Self {
            blocks,
            overall_entropy: overall,
            min_entropy: if min_e > 8.0 { 0.0 } else { min_e },
            max_entropy: max_e,
            mean_entropy: mean_e,
        }
    }
}

/*
 * calculate Shannon entropy of a byte slice:
 * H(X) = - sum(p(x) * log2(p(x)))
 * Ranges from 0.0 (uniform bytes, nulls/NOPs) to 8.0 (completely random or encrypted).
 */
#[inline]
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}
