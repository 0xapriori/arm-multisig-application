//! Byte-exact reimplementation of `RiscZeroUtils.toJournal(Logic.Instance)` from
//! `anoma/pa-evm` v1.1.0, plus its SHA256 digest.
//!
//! Conformance: see `tests/journal_conformance.rs` — fixtures are dumped from the Solidity
//! `LogicJournal` library; this Rust encoder must produce the same bytes for the same input.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeletionCriterion {
    Immediately = 0,
    Never = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirableBlob {
    pub deletion_criterion: DeletionCriterion,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppData {
    pub resource_payload: Vec<ExpirableBlob>,
    pub discovery_payload: Vec<ExpirableBlob>,
    pub external_payload: Vec<ExpirableBlob>,
    pub application_payload: Vec<ExpirableBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicInstance {
    pub tag: [u8; 32],
    pub is_consumed: bool,
    pub action_tree_root: [u8; 32],
    pub app_data: AppData,
}

/// Encode the Logic.Instance into the RISC Zero journal byte layout.
///
/// Layout (matches `RiscZeroUtils.toJournal`):
///     tag                         32 bytes
///     isConsumed                   4 bytes (uint32 little-endian: true=0x01000000 stored as 01,00,00,00)
///     actionTreeRoot              32 bytes
///     resourcePayload_len          4 bytes (uint32 little-endian)
///     resourcePayload_blobs        ...
///     discoveryPayload_len         4 bytes (uint32 little-endian)
///     discoveryPayload_blobs       ...
///     externalPayload_len          4 bytes (uint32 little-endian)
///     externalPayload_blobs        ...
///     applicationPayload_len       4 bytes (uint32 little-endian)
///     applicationPayload_blobs     ...
///
/// Each blob: deletion_criterion (1 byte, u8) || blob_len (4 bytes uint32 LE) || blob_bytes
pub fn encode(instance: &LogicInstance) -> Vec<u8> {
    let mut out = Vec::with_capacity(estimate_size(instance));

    out.extend_from_slice(&instance.tag);

    // isConsumed encoded as a u32 in little-endian. Solidity's `0x01000000` constant for `true`
    // is the byte sequence (0x01, 0x00, 0x00, 0x00) when laid out big-endian; that IS the
    // little-endian encoding of u32 = 1.
    let bool_le: u32 = if instance.is_consumed { 1 } else { 0 };
    out.extend_from_slice(&bool_le.to_le_bytes());

    out.extend_from_slice(&instance.action_tree_root);

    encode_payload(&mut out, &instance.app_data.resource_payload);
    encode_payload(&mut out, &instance.app_data.discovery_payload);
    encode_payload(&mut out, &instance.app_data.external_payload);
    encode_payload(&mut out, &instance.app_data.application_payload);

    out
}

fn encode_payload(out: &mut Vec<u8>, payload: &[ExpirableBlob]) {
    let len = u32::try_from(payload.len()).expect("payload too long for uint32");
    out.extend_from_slice(&len.to_le_bytes());
    for blob in payload {
        out.push(blob.deletion_criterion as u8);
        let blob_len = u32::try_from(blob.blob.len()).expect("blob too long for uint32");
        out.extend_from_slice(&blob_len.to_le_bytes());
        out.extend_from_slice(&blob.blob);
    }
}

/// SHA256 of `encode(instance)`. Matches PA's `journalDigest = sha256(toJournal(instance))`.
pub fn digest(instance: &LogicInstance) -> [u8; 32] {
    let bytes = encode(instance);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

fn estimate_size(instance: &LogicInstance) -> usize {
    let mut s = 32 + 4 + 32 + 4 * 4;
    for p in [
        &instance.app_data.resource_payload,
        &instance.app_data.discovery_payload,
        &instance.app_data.external_payload,
        &instance.app_data.application_payload,
    ] {
        for b in p {
            s += 1 + 4 + b.blob.len();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_layout() {
        let mut tag = [0u8; 32];
        tag[30..].copy_from_slice(&[0xaa, 0xaa]);
        let mut atr = [0u8; 32];
        atr[30..].copy_from_slice(&[0xbb, 0xbb]);

        let ins = LogicInstance {
            tag,
            is_consumed: false,
            action_tree_root: atr,
            app_data: AppData::default(),
        };

        let enc = encode(&ins);
        // 32 (tag) + 4 (bool_le) + 32 (root) + 4*4 (four empty payload length prefixes)
        assert_eq!(enc.len(), 32 + 4 + 32 + 16);
        // bool_le for false is four zero bytes
        assert_eq!(&enc[32..36], &[0, 0, 0, 0]);
        // Each empty payload length prefix is four zero bytes
        assert_eq!(&enc[68..], &[0u8; 16]);
    }
}
