//! Red-team fuzz harness: byte-level mutation fuzzing of MimeParser.
//!
//! A parser panic on the Mirror path means the session is published with
//! is_complete=false (or the parse path aborts), i.e. the mail silently
//! escapes content inspection. Any panic found here is a detection bypass.
//!
//! Run: cargo test --release -p vigilyx-parser --test redteam_fuzz -- --nocapture

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use vigilyx_parser::MimeParser;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(raw: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = raw.to_vec();
    if data.is_empty() {
        data.extend_from_slice(b"From: a@b.c\r\nSubject: t\r\n\r\nbody");
    }
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        if data.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                // flip byte
                let i = rng.below(data.len());
                data[i] ^= (1 << rng.below(8)) as u8;
            }
            1 => {
                // insert interesting byte
                let interesting = [
                    b'"', b';', b'=', b'?', b'@', b'<', b'>', b'\r', b'\n', b'\t', b' ', 0x80,
                    0xff, b'\\', b'/', b'(', b')', b'[', b']',
                ];
                let i = rng.below(data.len());
                data.insert(i, interesting[rng.below(interesting.len())]);
            }
            2 => {
                // delete range
                let i = rng.below(data.len());
                let len = 1 + rng.below(32.min(data.len() - i));
                data.drain(i..i + len);
            }
            3 => {
                // duplicate chunk (structure amplification)
                let i = rng.below(data.len());
                let len = 1 + rng.below(64.min(data.len() - i));
                let chunk = data[i..i + len].to_vec();
                data.extend_from_slice(&chunk);
            }
            4 => {
                // splice two regions
                let i = rng.below(data.len());
                let j = rng.below(data.len());
                data.swap(i, j);
            }
            _ => {
                // overwrite with CRLF-heavy runs (header boundary confusion)
                let i = rng.below(data.len());
                let len = 1 + rng.below(8.min(data.len() - i));
                for k in 0..len {
                    data[i + k] = if k % 2 == 0 { b'\r' } else { b'\n' };
                }
            }
        }
    }
    data
}

#[test]
fn fuzz_mime_parser_no_panics() {
    let seed_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vigilyx-engine/tests/redteam_cases");
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&seed_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "eml") {
                if let Ok(raw) = std::fs::read(&p) {
                    seeds.push(raw);
                }
            }
        }
    }
    if seeds.is_empty() {
        seeds.push(b"From: a@b.c\r\nTo: d@e.f\r\nSubject: s\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"X\"\r\n\r\n\
--X\r\nContent-Type: text/plain\r\n\r\nhi\r\n--X--\r\n"
            .to_vec());
    }

    let iterations: usize = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let mut rng = Rng(0x853c49e6748fea9b ^ std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64);

    let parser = MimeParser::new();
    let mut panics: Vec<String> = Vec::new();
    let mut ok = 0usize;
    let mut err = 0usize;

    for i in 0..iterations {
        let seed = &seeds[rng.below(seeds.len())];
        let input = mutate(seed, &mut rng);
        match catch_unwind(AssertUnwindSafe(|| parser.parse(&input))) {
            Ok(Ok(_)) => ok += 1,
            Ok(Err(_)) => err += 1,
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "(non-string panic)".into());
                // Persist the exact input for the report.
                let path = std::env::temp_dir().join(format!("vigilyx_fuzz_panic_{i}.bin"));
                std::fs::write(&path, &input).expect("write crash input");
                eprintln!("PANIC at iter {i}: {msg} — input saved to {}", path.display());
                panics.push(format!("iter {i}: {msg} ({})", path.display()));
                if panics.len() >= 10 {
                    break;
                }
            }
        }
    }

    println!(
        "fuzz done: {iterations} iters, ok={ok}, err={err}, panics={}",
        panics.len()
    );
    assert!(
        panics.is_empty(),
        "MimeParser panicked on {} inputs (Mirror-path detection bypass):\n{}",
        panics.len(),
        panics.join("\n")
    );
}
