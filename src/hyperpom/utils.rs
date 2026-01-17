/// A fast log2 implementation for `usize` equivalent to `(x as f64).log2().ceil()`.
#[inline]
pub fn log2(x: usize) -> usize {
    let (orig_x, mut x, mut log) = (x, x, 0);
    while x != 0 {
        x >>= 1;
        log += 1;
    }
    log - 1 + ((orig_x & (orig_x - 1)) != 0) as usize
}

/// A fast log2 implementation for `usize` equivalent to `(x as f64).log2().floor()`.
#[inline]
pub fn log2_floor(x: usize) -> usize {
    let mut x = x;
    let mut log = 0;
    while x != 0 {
        x >>= 1;
        log += 1;
    }
    log - 1
}
