//! Portbit - O(1) Portmatch (cache-line aligned)

//! HashSet Vec::contains 10-50

/// Portbit,Used for O(1) timestamp ofPortmatch
/// cache-line alignedEnsure Memoryaccessmode
/// HashSet Vec::contains 10-50
#[repr(C, align(64))]
pub struct PortBitmap {
   /// bit Array (65536 bit = 8KB)
   /// Use Box Ensure Allocate,Avoid Overflow
    bitmap: Box<[u64; 1024]>,
}

impl PortBitmap {
   /// Create bit
    pub fn new() -> Self {
        Self {
            bitmap: Box::new([0u64; 1024]),
        }
    }

   /// FromPortListCreatebit
    pub fn from_ports(ports: &[u16]) -> Self {
        let mut bm = Self::new();
        for &port in ports {
            bm.set(port);
        }
        bm
    }

   /// SetPort
    #[inline(always)]
    pub fn set(&mut self, port: u16) {
        let idx = (port / 64) as usize;
        let bit = port % 64;
        self.bitmap[idx] |= 1u64 << bit;
    }

   /// CheckPortwhetherstored - O(1)
   /// Usebit EnsureBranch
    #[inline(always)]
    #[allow(dead_code)]
    pub fn contains(&self, port: u16) -> bool {
        let idx = (port / 64) as usize;
        let bit = port % 64;
       // UseAccording tobit Ensure Branch
        (self.bitmap[idx] & (1u64 << bit)) != 0
    }

   /// Samewhen checking Port (Performance notes PortScenario)
    #[inline(always)]
    pub fn contains_either(&self, port1: u16, port2: u16) -> (bool, bool) {
        let idx1 = (port1 / 64) as usize;
        let bit1 = port1 % 64;
        let idx2 = (port2 / 64) as usize;
        let bit2 = port2 % 64;

        let match1 = (self.bitmap[idx1] & (1u64 << bit1)) != 0;
        let match2 = (self.bitmap[idx2] & (1u64 << bit2)) != 0;

        (match1, match2)
    }
}
