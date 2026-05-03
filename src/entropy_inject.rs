use std::time::Instant;
use std::collections::VecDeque;

const ENTROPY_POOL_SIZE: usize = 256;
const MIN_ENTROPY_BITS: usize = 256;

pub struct EntropyCollector {
    buffer: VecDeque<u64>,
    sample_count: usize,
}

impl EntropyCollector {
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(ENTROPY_POOL_SIZE),
            sample_count: 0,
        }
    }
    
    pub fn collect(&mut self) -> usize {
        let mut collected = 0;
        
        // CPU timing jitter
        for _ in 0..10 {
            let start = Instant::now();
            let _ = (0..100).sum::<u64>();
            let end = Instant::now();
            let jitter = (end - start).as_nanos() as u64;
            self.buffer.push_back(jitter);
            collected += 1;
        }
        
        // Add process memory info (rough entropy)
        self.buffer.push_back(collected as u64);
        self.buffer.push_back(self.sample_count as u64);
        
        self.sample_count += collected;
        
        if self.buffer.len() > ENTROPY_POOL_SIZE {
            self.buffer.pop_front();
        }
        
        collected
    }
    
    pub fn is_ready(&self) -> bool {
        self.sample_count >= MIN_ENTROPY_BITS / 8
    }
    
    pub fn get_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        let mut i = 0;
        
        for &val in self.buffer.iter() {
            if i >= 32 { break; }
            let bytes = val.to_le_bytes();
            for b in bytes {
                if i >= 32 { break; }
                seed[i] = seed[i].wrapping_add(b);
                i += 1;
            }
        }
        
        // Mix in sample count
        let cnt = self.sample_count.to_le_bytes();
        for (j, &b) in cnt.iter().enumerate() {
            if j < 4 {
                seed[j] = seed[j].wrapping_add(b);
            }
        }
        
        seed
    }
}

impl Default for EntropyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy_collection() {
        let mut collector = EntropyCollector::new();
        
        for _ in 0..5 {
            collector.collect();
        }
        
        assert!(collector.sample_count > 0);
        
        let seed = collector.get_seed();
        assert!(!seed.iter().all(|&x| x == 0));
    }
}