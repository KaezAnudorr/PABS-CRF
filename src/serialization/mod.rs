use std::io::Read;

use crate::compression::{
    decode_challenge, encode_challenge, pack_hints, pack_polyvec_mod_q, pack_z, unpack_hints,
    unpack_polyvec_mod_q, unpack_z,
};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::PolynomialVector;
use crate::pabs::types::{CompressedFirewallSignature, FirewallSignature};

const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

pub fn compress_firewall_signature(
    signature: &FirewallSignature,
    witness_rows: Vec<u16>,
    params: &crate::mlwe::MLWEParameters,
) -> CompressedFirewallSignature {
    let z_centered = signature.z.center_coefficients(params.q);
    CompressedFirewallSignature {
        packed_z: pack_z(&z_centered, params.gamma1, params.n),
        encoded_c: encode_challenge(&signature.challenge, params.n),
        packed_hints: signature.hints.as_ref().map(pack_hints),
        packed_delta: pack_polyvec_mod_q(&signature.firewall_delta, params.q),
        witness_rows,
        policy_digest: signature.policy_digest.clone(),
        firewall_tag: signature.firewall_tag.clone(),
        parameter_set_id: signature.parameter_set_id.clone(),
        pk_hash: signature.pk_hash.clone(),
        crf_seed: None,
        tau: signature.tau,
        gid: signature.gid,
    }
}

pub fn decompress_firewall_signature(
    compressed: &CompressedFirewallSignature,
    policy: crate::policy::Policy,
    message_hash: Vec<u8>,
    attributes_used: Vec<String>,
    params: &crate::mlwe::MLWEParameters,
) -> PabsCrfResult<FirewallSignature> {
    let z_centered = unpack_z(&compressed.packed_z, params.m, params.n, params.gamma1)?;
    let z = PolynomialVector {
        elements: z_centered
            .elements
            .iter()
            .map(|p| crate::mlwe::Polynomial::from_coeffs(&p.coeffs, params.q))
            .collect(),
    };
    Ok(FirewallSignature {
        z,
        challenge: decode_challenge(&compressed.encoded_c, params.n),
        hints: compressed
            .packed_hints
            .as_ref()
            .map(|blob| unpack_hints(blob, params.k, params.n))
            .transpose()?,
        policy,
        message_hash,
        attributes_used,
        policy_digest: compressed.policy_digest.clone(),
        firewall_delta: unpack_polyvec_mod_q(
            &compressed.packed_delta,
            params.k,
            params.n,
            params.q,
        )?,
        firewall_tag: compressed.firewall_tag.clone(),
        parameter_set_id: compressed.parameter_set_id.clone(),
        pk_hash: compressed.pk_hash.clone(),
        crf_seed: None,
        tau: compressed.tau,
        gid: compressed.gid,
    })
}

const COMPACT_MAGIC: [u8; 4] = *b"PABS";
const COMPACT_VERSION: u8 = 2;
const ZSTD_LEVEL: i32 = 3;

pub struct LayoutBreakdown {
    pub header: usize,
    pub packed_z: usize,
    pub packed_delta: usize,
    pub encoded_c: usize,
    pub packed_hints: usize,
    pub pk_hash: usize,
    pub witness_rows: usize,
    pub param_id: usize,
    pub trailer: usize,
    pub raw_total: usize,
    pub zstd_compressed: usize,
}

pub fn measure_layout(compressed: &CompressedFirewallSignature) -> PabsCrfResult<LayoutBreakdown> {
    let hints_bytes = compressed.packed_hints.as_deref().unwrap_or(&[]);
    let param_id_bytes = compressed.parameter_set_id.as_bytes();
    let wr_count = compressed.witness_rows.len();

    let z = compressed.packed_z.len();
    let delta = compressed.packed_delta.len();
    let c = compressed.encoded_c.len();
    let hints = hints_bytes.len();
    let pkh = compressed.pk_hash.len();
    let wr = wr_count * 2;
    let pid = param_id_bytes.len();

    let raw_total = HEADER_SIZE + z + delta + c + hints + pkh + wr + pid + TRAILER_SIZE;
    let blob = serialize_compressed_signature(compressed)?;

    Ok(LayoutBreakdown {
        header: HEADER_SIZE,
        packed_z: z,
        packed_delta: delta,
        encoded_c: c,
        packed_hints: hints,
        pk_hash: pkh,
        witness_rows: wr,
        param_id: pid,
        trailer: TRAILER_SIZE,
        raw_total,
        zstd_compressed: blob.len(),
    })
}

/// Compact binary layout (v2 — no variable-length z encoding):
/// ```text
/// HEADER:  [magic:4][ver:1][tau:8][gid:32][policy_digest:32][firewall_tag:32]
///          [pk_hash_len:2][param_id_len:1][wr_count:2]  = 114 bytes
/// FIELDS:  [z_bytes...][delta_bytes...][c_bytes...][hints_bytes...]
///          [pk_hash_bytes...][wr_rows:wr_count*2][param_id_bytes...]
/// TRAILER: [z_len:2][delta_len:2][c_len:2][hints_len:2]
///          [pkh_len:2][wr_count:2][pid_len:1]  = 13 bytes
/// ```

const HEADER_SIZE: usize = 114;
const TRAILER_SIZE: usize = 13;

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u16(buf: &[u8], off: &mut usize) -> PabsCrfResult<u16> {
    if *off + 2 > buf.len() {
        return Err(PabsCrfError::DeserializationError("truncated u16".into()));
    }
    let v = u16::from_le_bytes([buf[*off], buf[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_bytes<'a>(buf: &'a [u8], off: &mut usize, len: usize) -> PabsCrfResult<&'a [u8]> {
    if *off + len > buf.len() {
        return Err(PabsCrfError::DeserializationError("truncated field".into()));
    }
    let slice = &buf[*off..*off + len];
    *off += len;
    Ok(slice)
}

pub fn serialize_compressed_signature(
    compressed: &CompressedFirewallSignature,
) -> PabsCrfResult<Vec<u8>> {
    let hints_bytes = compressed.packed_hints.as_deref().unwrap_or(&[]);
    let param_id_bytes = compressed.parameter_set_id.as_bytes();
    let pk_hash_len = compressed.pk_hash.len() as u16;
    let wr_count = compressed.witness_rows.len() as u16;

    let total_field_bytes = compressed.packed_z.len()
        + compressed.packed_delta.len()
        + compressed.encoded_c.len()
        + hints_bytes.len()
        + compressed.pk_hash.len()
        + (wr_count as usize) * 2
        + param_id_bytes.len();

    let mut raw = Vec::with_capacity(HEADER_SIZE + total_field_bytes + TRAILER_SIZE);

    raw.extend_from_slice(&COMPACT_MAGIC);
    raw.push(COMPACT_VERSION);
    raw.extend_from_slice(&compressed.tau.to_le_bytes());
    raw.extend_from_slice(&compressed.gid);
    raw.extend_from_slice(&compressed.policy_digest);
    raw.extend_from_slice(&compressed.firewall_tag);
    write_u16(&mut raw, pk_hash_len);
    raw.push(param_id_bytes.len() as u8);
    write_u16(&mut raw, wr_count);

    raw.extend_from_slice(&compressed.packed_z);
    raw.extend_from_slice(&compressed.packed_delta);
    raw.extend_from_slice(&compressed.encoded_c);
    raw.extend_from_slice(hints_bytes);
    raw.extend_from_slice(&compressed.pk_hash);
    for &row in &compressed.witness_rows {
        write_u16(&mut raw, row);
    }
    raw.extend_from_slice(param_id_bytes);

    write_u16(&mut raw, compressed.packed_z.len() as u16);
    write_u16(&mut raw, compressed.packed_delta.len() as u16);
    write_u16(&mut raw, compressed.encoded_c.len() as u16);
    write_u16(&mut raw, hints_bytes.len() as u16);
    write_u16(&mut raw, compressed.pk_hash.len() as u16);
    write_u16(&mut raw, wr_count);
    raw.push(param_id_bytes.len() as u8);

    zstd::encode_all(raw.as_slice(), ZSTD_LEVEL)
        .map_err(|e| PabsCrfError::CompressionError(format!("zstd compress failed: {}", e)))
}

pub fn deserialize_compressed_signature(blob: &[u8]) -> PabsCrfResult<CompressedFirewallSignature> {
    let mut decoder = zstd::Decoder::new(blob)
        .map_err(|e| PabsCrfError::CompressionError(format!("zstd decoder: {}", e)))?;
    let mut raw = Vec::new();
    decoder
        .take((MAX_DECOMPRESSED_SIZE as u64) + 1)
        .read_to_end(&mut raw)
        .map_err(|e| PabsCrfError::CompressionError(format!("zstd decompress: {}", e)))?;
    if raw.len() > MAX_DECOMPRESSED_SIZE {
        return Err(PabsCrfError::CompressionError(format!(
            "decompressed {} exceeds {}",
            raw.len(),
            MAX_DECOMPRESSED_SIZE
        )));
    }
    if raw.len() < HEADER_SIZE + TRAILER_SIZE {
        return Err(PabsCrfError::DeserializationError("blob too short".into()));
    }

    let mut off = 0usize;
    let magic = read_bytes(&raw, &mut off, 4)?;
    if magic != COMPACT_MAGIC {
        return Err(PabsCrfError::DeserializationError("bad magic".into()));
    }
    let version = raw[off];
    off += 1;
    if version != COMPACT_VERSION {
        return Err(PabsCrfError::DeserializationError(format!(
            "unsupported version {}",
            version
        )));
    }

    let mut tau_buf = [0u8; 8];
    tau_buf.copy_from_slice(read_bytes(&raw, &mut off, 8)?);
    let tau = u64::from_le_bytes(tau_buf);

    let mut gid = [0u8; 32];
    gid.copy_from_slice(read_bytes(&raw, &mut off, 32)?);

    let mut policy_digest = vec![0u8; 32];
    policy_digest.copy_from_slice(read_bytes(&raw, &mut off, 32)?);

    let mut firewall_tag = vec![0u8; 32];
    firewall_tag.copy_from_slice(read_bytes(&raw, &mut off, 32)?);

    let pk_hash_len_field = read_u16(&raw, &mut off)? as usize;
    let param_id_len_field = raw[off] as usize;
    off += 1;
    let wr_count_field = read_u16(&raw, &mut off)? as usize;

    let fields_start = off;

    let trailer_start = raw.len() - TRAILER_SIZE;
    let mut toff = trailer_start;
    let z_len = read_u16(&raw, &mut toff)? as usize;
    let delta_len = read_u16(&raw, &mut toff)? as usize;
    let c_len = read_u16(&raw, &mut toff)? as usize;
    let hints_len = read_u16(&raw, &mut toff)? as usize;
    let pkh_len = read_u16(&raw, &mut toff)? as usize;
    let wr_count_t = read_u16(&raw, &mut toff)? as usize;
    let pid_len = raw[toff] as usize;

    let expected_field_bytes =
        z_len + delta_len + c_len + hints_len + pkh_len + wr_count_t * 2 + pid_len;
    if fields_start + expected_field_bytes + TRAILER_SIZE != raw.len() {
        return Err(PabsCrfError::DeserializationError(format!(
            "field lengths mismatch: fields_start={} expected={} raw_len={}",
            fields_start,
            expected_field_bytes,
            raw.len()
        )));
    }

    let mut foff = fields_start;
    let packed_z = read_bytes(&raw, &mut foff, z_len)?.to_vec();
    let packed_delta = read_bytes(&raw, &mut foff, delta_len)?.to_vec();
    let encoded_c = read_bytes(&raw, &mut foff, c_len)?.to_vec();
    let packed_hints_blob = read_bytes(&raw, &mut foff, hints_len)?;
    let packed_hints = if hints_len > 0 {
        Some(packed_hints_blob.to_vec())
    } else {
        None
    };
    let pk_hash = read_bytes(&raw, &mut foff, pkh_len)?.to_vec();
    let mut witness_rows = Vec::with_capacity(wr_count_t);
    for _ in 0..wr_count_t {
        witness_rows.push(read_u16(&raw, &mut foff)?);
    }
    let parameter_set_id = String::from_utf8(read_bytes(&raw, &mut foff, pid_len)?.to_vec())
        .map_err(|_| {
            PabsCrfError::DeserializationError("invalid utf-8 in parameter_set_id".into())
        })?;

    if pk_hash_len_field != pkh_len || wr_count_field != wr_count_t || param_id_len_field != pid_len
    {
        return Err(PabsCrfError::DeserializationError(
            "header/trailer length mismatch".into(),
        ));
    }

    Ok(CompressedFirewallSignature {
        packed_z,
        encoded_c,
        packed_hints,
        packed_delta,
        witness_rows,
        policy_digest,
        firewall_tag,
        parameter_set_id,
        pk_hash,
        crf_seed: None,
        tau,
        gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_compressed_sig() -> CompressedFirewallSignature {
        CompressedFirewallSignature {
            packed_z: vec![0u8; 64],
            encoded_c: vec![0u8; 32],
            packed_hints: None,
            packed_delta: vec![0u8; 64],
            witness_rows: vec![0],
            policy_digest: vec![0u8; 32],
            firewall_tag: vec![0u8; 32],
            parameter_set_id: "top-tier-128".to_string(),
            pk_hash: Vec::new(),
            crf_seed: None,
            tau: 0,
            gid: [0u8; 32],
        }
    }

    #[test]
    fn test_valid_signature_roundtrip() {
        let sig = make_minimal_compressed_sig();
        let blob = serialize_compressed_signature(&sig).expect("serialization should succeed");
        let recovered =
            deserialize_compressed_signature(&blob).expect("deserialization should succeed");
        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_nonzero_z_roundtrip() {
        let mut sig = make_minimal_compressed_sig();
        sig.packed_z = (0..128).map(|i| (i * 7 + 3) as u8).collect();
        let blob = serialize_compressed_signature(&sig).expect("serialization should succeed");
        let recovered =
            deserialize_compressed_signature(&blob).expect("deserialization should succeed");
        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_zstd_decompress_size_limit() {
        let oversized_raw = vec![0u8; 11 * 1024 * 1024];
        let compressed_blob = zstd::encode_all(oversized_raw.as_slice(), 1)
            .expect("compressing zeros should succeed");
        let result = deserialize_compressed_signature(&compressed_blob);
        match result {
            Err(PabsCrfError::CompressionError(msg)) => {
                assert!(
                    msg.contains("exceeds"),
                    "Expected size-limit error, got: {}",
                    msg
                );
            }
            other => panic!("Expected CompressionError, got: {:?}", other),
        }
    }
}
