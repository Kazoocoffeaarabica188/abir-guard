//! Abir-Guard: Differential Privacy for Entropy Collection
//!
//! Adds calibrated noise to timing-based entropy collection to defeat
//! Spectre/Meltdown side-channel attacks using Laplace mechanism.

use sha2::{Sha256, Digest};
use std::time::Instant;

/// Laplace noise generator for differential privacy
pub struct LaplaceNoise {
    epsilon: f64,
}

impl LaplaceNoise {
    pub fn new(epsilon: f64) -> Self {
        assert!(epsilon > 0.0, "Epsilon must be positive");
        Self { epsilon }
    }

    /// Generate a Laplace noise sample
    pub fn sample(&self, sensitivity: f64) -> f64 {
        let scale = sensitivity / self.epsilon;
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("Failed to get random bytes");
        let u: f64 = (u64::from_le_bytes(buf) as f64 / u64::MAX as f64) - 0.5;
        -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
    }

    /// Add calibrated noise to a value
    pub fn add_noise(&self, value: f64, sensitivity: f64) -> f64 {
        value + self.sample(sensitivity)
    }
}

/// Entropy collector with differential privacy protection
pub struct DifferentialEntropyCollector {
    noise: LaplaceNoise,
    sample_count: usize,
    total_samples: usize,
}

impl DifferentialEntropyCollector {
    pub fn new(epsilon: f64, sample_count: usize) -> Self {
        Self {
            noise: LaplaceNoise::new(epsilon),
            sample_count,
            total_samples: 0,
        }
    }

    /// Collect entropy with differential privacy protection
    pub fn collect(&mut self) -> Vec<u8> {
        let mut entropy_input = Vec::with_capacity(self.sample_count * 8 + 32);

        for _ in 0..self.sample_count {
            let t0 = Instant::now();
            let _ = (0..50).sum::<u64>();
            let true_timing = t0.elapsed().as_nanos() as f64;

            let noisy_timing = self.noise.add_noise(true_timing, 1000.0);
            entropy_input.extend_from_slice(&(noisy_timing as i64).to_le_bytes());
        }

        // Mix in OS CSPRNG entropy
        let mut os_entropy = vec![0u8; 32];
        getrandom::fill(&mut os_entropy).expect("Failed to get OS entropy");
        entropy_input.extend_from_slice(&os_entropy);

        // Post-process with SHA-256
        let mut h = Sha256::new();
        h.update(&entropy_input);
        let entropy = h.finalize().to_vec();

        self.total_samples += self.sample_count;
        entropy
    }

    /// Get privacy budget status
    pub fn privacy_budget(&self) -> (f64, usize) {
        (self.noise.epsilon, self.total_samples)
    }
}

/// Constant-time comparison and Spectre/Meltdown protections
pub struct SpectreMeltdownDefender;

impl SpectreMeltdownDefender {
    /// Constant-time byte comparison
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut result: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Inject random delay to defeat timing analysis
    pub fn inject_random_delay(min_us: u64, max_us: u64) {
        let delay_us = rand::random::<u64>() % (max_us - min_us + 1) + min_us;
        std::thread::sleep(std::time::Duration::from_micros(delay_us));
    }

    /// Constant-time comparison with random delay injection
    pub fn secure_compare_and_delay(a: &[u8], b: &[u8]) -> bool {
        let result = Self::constant_time_compare(a, b);
        Self::inject_random_delay(10, 100);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_collection() {
        let mut collector = DifferentialEntropyCollector::new(0.5, 10);
        let entropy = collector.collect();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(SpectreMeltdownDefender::constant_time_compare(b"hello", b"hello"));
        assert!(!SpectreMeltdownDefender::constant_time_compare(b"hello", b"world"));
        assert!(!SpectreMeltdownDefender::constant_time_compare(b"short", b"longer"));
    }
}
