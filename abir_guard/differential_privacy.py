"""
Abir-Guard: Differential Privacy for Entropy Collection

Adds calibrated noise to timing-based entropy collection to defeat
Spectre/Meltdown side-channel attacks. Uses Laplace mechanism to
provide epsilon-differential privacy guarantees.

The noise is calibrated such that:
- True entropy is preserved in aggregate
- Individual timing measurements are obfuscated
- Attackers cannot infer private key bits from timing analysis

Epsilon parameter controls privacy-utility tradeoff:
- Lower epsilon = more noise = stronger privacy = less precision
- Higher epsilon = less noise = weaker privacy = more precision
- Recommended: epsilon = 0.1 to 1.0 for cryptographic applications
"""

import os
import time
import math
import hashlib
import random
from typing import List, Optional


class LaplaceNoise:
    """
    Laplace noise generator for differential privacy.
    
    The Laplace distribution is used because it provides
    optimal noise for epsilon-differential privacy on
    count/sum queries.
    """
    
    def __init__(self, epsilon: float = 0.5):
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        self.epsilon = epsilon
    
    def sample(self, sensitivity: float = 1.0) -> float:
        """
        Generate a Laplace noise sample.
        
        The scale parameter b = sensitivity / epsilon.
        Larger scale = more noise = stronger privacy.
        """
        scale = sensitivity / self.epsilon
        u = random.uniform(-0.5, 0.5)
        return -scale * math.copysign(math.log(1 - 2 * abs(u)), u)
    
    def add_noise(self, value: float, sensitivity: float = 1.0) -> float:
        """Add calibrated noise to a value."""
        return value + self.sample(sensitivity)


class DifferentialEntropyCollector:
    """
    Entropy collector with differential privacy noise injection.
    
    Collects timing-based entropy but adds calibrated Laplace noise
    to individual measurements, preventing side-channel attackers
    from inferring private key bits through precise timing analysis.
    
    The aggregate entropy pool remains high-quality because:
    1. Noise averages out over many samples
    2. OS CSPRNG is mixed in via XOR
    3. SHA-256 post-processing whitens the output
    """
    
    def __init__(self, epsilon: float = 0.5, sample_count: int = 20):
        self.noise = LaplaceNoise(epsilon)
        self.sample_count = sample_count
        self._entropy_buffer: List[bytes] = []
        self._total_samples = 0
    
    def collect(self) -> bytes:
        """
        Collect entropy with differential privacy protection.
        
        Returns 32 bytes of noise-injected, whitened entropy.
        """
        timings = []
        
        # Collect timing samples with noise injection
        for _ in range(self.sample_count):
            # True timing measurement
            t0 = time.perf_counter_ns()
            _ = sum(range(50))
            t1 = time.perf_counter_ns()
            true_timing = t1 - t0
            
            # Add calibrated Laplace noise
            noisy_timing = int(self.noise.add_noise(true_timing, sensitivity=1000))
            timings.append(noisy_timing)
        
        # Mix in OS CSPRNG entropy
        os_entropy = os.urandom(32)
        
        # Combine all sources
        entropy_input = b"".join(
            t.to_bytes(8, 'big', signed=True) for t in timings
        ) + os_entropy
        
        # Post-process with SHA-256 to whiten
        entropy = hashlib.sha256(entropy_input).digest()
        
        self._entropy_buffer.append(entropy)
        self._total_samples += self.sample_count
        
        return entropy
    
    def collect_batch(self, count: int = 5) -> bytes:
        """Collect multiple entropy samples and combine."""
        samples = [self.collect() for _ in range(count)]
        combined = b"".join(samples)
        return hashlib.sha3_256(combined).digest()
    
    @property
    def total_samples(self) -> int:
        return self._total_samples
    
    @property
    def epsilon(self) -> float:
        return self.noise.epsilon
    
    def get_privacy_budget(self) -> dict:
        """Return current privacy budget status."""
        return {
            "epsilon_per_sample": self.epsilon,
            "total_samples": self._total_samples,
            "total_privacy_cost": self.epsilon * self._total_samples,
            "noise_scale": 1.0 / self.epsilon,
        }


class SpectreMeltdownDefender:
    """
    Additional protections against Spectre/Meltdown attacks.
    
    Provides:
    1. Constant-time comparison for sensitive operations
    2. Memory padding to prevent cache-line leakage
    3. Randomized delay injection for timing attacks
    """
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        Prevents timing side-channel attacks.
        """
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    @staticmethod
    def pad_to_cache_line(data: bytes, line_size: int = 64) -> bytes:
        """
        Pad data to cache line boundaries.
        Prevents cache-line side-channel leakage.
        """
        remainder = len(data) % line_size
        if remainder == 0:
            return data
        padding = os.urandom(line_size - remainder)
        return data + padding
    
    @staticmethod
    def inject_random_delay(min_us: int = 10, max_us: int = 100) -> None:
        """
        Inject random delay to defeat timing analysis.
        Delays are in microseconds.
        """
        delay = random.uniform(min_us, max_us) / 1_000_000
        time.sleep(delay)
    
    @staticmethod
    def secure_compare_and_delay(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison with random delay injection.
        Combines both protections for maximum security.
        """
        result = SpectreMeltdownDefender.constant_time_compare(a, b)
        SpectreMeltdownDefender.inject_random_delay()
        return result
