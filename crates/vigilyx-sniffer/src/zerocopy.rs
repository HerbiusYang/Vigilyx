//! Batch processing optimization module

//! ProvideHigh-performance data packet ProcessingBatch:
//! - adaptiveBatchsizeadjust
//! - Exponential moving averageStatistics

/// Batch packet process configuration
#[derive(Clone, Debug)]
pub struct BatchConfig {
   /// Batch size
    pub batch_size: usize,
   /// timeout duration (microseconds)
    #[allow(dead_code)]
    pub timeout_us: u64,
   /// Whether to enable adaptive Batch
    pub adaptive: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            timeout_us: 5000, // 5ms
            adaptive: true,
        }
    }
}

/// adaptive Batch process device/Handler
pub struct AdaptiveBatcher {
    config: BatchConfig,
   /// When first recommended batch size
    current_batch_size: usize,
   /// previous batch process timestamp (nanoseconds)
    last_batch_time_ns: u64,
   /// average per packet process timestamp (nanoseconds)
    avg_packet_time_ns: u64,
}

impl AdaptiveBatcher {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            current_batch_size: config.batch_size,
            config,
            last_batch_time_ns: 0,
            avg_packet_time_ns: 1000, // initial assumption 1s/packet
        }
    }

   /// Get When first recommended batch size
    #[inline]
    pub fn recommended_batch_size(&self) -> usize {
        self.current_batch_size
    }

   /// update Statistics and adjust batch size
    pub fn update(&mut self, packet_count: usize, elapsed_ns: u64) {
        if packet_count == 0 {
            return;
        }

       // calculate average process timestamp
        let avg = elapsed_ns / packet_count as u64;

       // exponential moving average
        let alpha = 0.1; // smoothing factor
        self.avg_packet_time_ns =
            ((1.0 - alpha) * self.avg_packet_time_ns as f64 + alpha * avg as f64) as u64;

       // adaptive adjust batch size
        if self.config.adaptive {
            if self.avg_packet_time_ns > 5000 {
               // process too slow, reduce batch
                self.current_batch_size = self.current_batch_size.saturating_sub(16).max(16);
            } else if self.avg_packet_time_ns < 1000 && self.current_batch_size < 1024 {
               // process fast and batch already full, increase batch
                self.current_batch_size = (self.current_batch_size + 16).min(1024);
            }
        }

        self.last_batch_time_ns = elapsed_ns;
    }

   /// Get current batch size (alias for recommended_batch_size)
    #[inline]
    #[allow(dead_code)]
    pub fn batch_size(&self) -> usize {
        self.current_batch_size
    }

   /// Get final statistics: (current_batch_size, avg_packet_time_ns)
    pub fn stats(&self) -> (usize, u64) {
        (self.current_batch_size, self.avg_packet_time_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_batcher() {
        let config = BatchConfig::default();
        let mut batcher = AdaptiveBatcher::new(config);

       // simulate fast process
        batcher.update(256, 100_000); // 256 packets in 100s

       // simulate slow process
        batcher.update(256, 2_000_000); // 256 packets in 2ms
    }
}
