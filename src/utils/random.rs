use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut state = seed;
    let mut bytes = Vec::with_capacity(size);

    for _ in 0..size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        bytes.push((state >> 33) as u8);
    }

    bytes
}
