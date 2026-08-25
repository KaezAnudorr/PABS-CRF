use crate::mlwe::PolynomialVector;

pub fn canonical_serialize_w1(w1: &PolynomialVector, m: u32) -> Vec<u8> {
    let bits_per_coeff = ((m as f64).log2().ceil() as usize).max(1);
    let total_bits = w1.elements.len() * w1.elements[0].coeffs.len() * bits_per_coeff;
    let total_bytes = (total_bits + 7) / 8;

    let mut out = Vec::with_capacity(total_bytes);
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    for poly in &w1.elements {
        for &c in &poly.coeffs {
            debug_assert!(
                c >= 0 && (c as u32) < m,
                "w1 coefficient {} out of [0, m={})",
                c,
                m
            );
            bit_buf |= (c as u64) << bit_count;
            bit_count += bits_per_coeff as u32;
            while bit_count >= 8 {
                out.push((bit_buf & 0xFF) as u8);
                bit_buf >>= 8;
                bit_count -= 8;
            }
        }
    }
    if bit_count > 0 {
        out.push((bit_buf & 0xFF) as u8);
    }
    out
}
