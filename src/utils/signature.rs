pub struct SignatureScanner;

impl SignatureScanner {
    pub fn unique_byte_count(data: &[u8]) -> usize {
        let mut seen = [false; 256];
        for &b in data {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&x| x).count()
    }

    pub fn max_run_length(data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        let mut max_run = 1;
        let mut current_run = 1;

        for i in 1..data.len() {
            if data[i] == data[i - 1] {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 1;
            }
        }

        max_run
    }

    pub fn count_matching<F>(data: &[u8], predicate: F) -> usize
    where
        F: Fn(u8) -> bool,
    {
        data.iter().filter(|&&b| predicate(b)).count()
    }

    pub fn looks_like_pointer(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        (data[6] == 0xff && data[7] == 0xff)
            || (data.len() >= 16 && data[14] == 0xff && data[15] == 0xff)
    }

    pub fn all_same(data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        data.iter().all(|&b| b == data[0])
    }

    pub fn all_zero(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }
}
