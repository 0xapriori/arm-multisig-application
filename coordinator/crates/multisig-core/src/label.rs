//! `label_preimage` encoding and `labelRef = SHA256(label_preimage)`.
//!
//! Per spec §4.2 (v0.4):
//!     label_preimage =
//!         "anoma.multisig.v1"   17 bytes
//!      || token_addr            20 bytes
//!      || n                      1 byte
//!      || k                      1 byte
//!      || pubkey_root           32 bytes
//!      || salt                  32 bytes
//!     = 103 bytes
//!
//! Pubkeys are 33-byte compressed secp256k1 points sorted lexicographically; pubkey_root =
//! SHA256(concat(sorted_pubkeys)).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MULTISIG_DOMAIN: &[u8] = b"anoma.multisig.v1";
pub const NULLIFIER_KEY_DOMAIN: &[u8] = b"anoma.multisig.v1.nfk-key";
pub const PREIMAGE_LEN: usize = 17 + 20 + 1 + 1 + 32 + 32;

#[derive(Debug, Error)]
pub enum LabelError {
    #[error("n out of range: must be 1..=32, got {0}")]
    InvalidN(u8),
    #[error("k out of range: must be 1..=n, got k={k}, n={n}")]
    InvalidK { k: u8, n: u8 },
    #[error("pubkey count mismatch: n={n}, |pubkeys|={got}")]
    PubkeyCountMismatch { n: u8, got: usize },
    #[error("salt must be non-zero")]
    ZeroSalt,
    #[error("pubkeys must be sorted ascending")]
    UnsortedPubkeys,
    #[error("compressed pubkey must be 33 bytes")]
    InvalidPubkeyLength,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelPreimage {
    pub token_addr: [u8; 20],
    pub n: u8,
    pub k: u8,
    pub pubkey_root: [u8; 32],
    pub salt: [u8; 32],
}

impl LabelPreimage {
    /// Build a label_preimage from validated inputs. Computes pubkey_root from sorted compressed pubkeys.
    pub fn new(
        token_addr: [u8; 20],
        k: u8,
        pubkeys: &[[u8; 33]],
        salt: [u8; 32],
    ) -> Result<Self, LabelError> {
        let n = u8::try_from(pubkeys.len()).map_err(|_| LabelError::InvalidN(0))?;
        if !(1..=32).contains(&n) {
            return Err(LabelError::InvalidN(n));
        }
        if k == 0 || k > n {
            return Err(LabelError::InvalidK { k, n });
        }
        if salt == [0u8; 32] {
            return Err(LabelError::ZeroSalt);
        }
        for w in pubkeys.windows(2) {
            if w[0] >= w[1] {
                return Err(LabelError::UnsortedPubkeys);
            }
        }
        let pubkey_root = pubkey_root_of(pubkeys);
        Ok(Self {
            token_addr,
            n,
            k,
            pubkey_root,
            salt,
        })
    }

    /// Serialize the label_preimage to its 103-byte canonical form.
    pub fn encode(&self) -> [u8; PREIMAGE_LEN] {
        let mut out = [0u8; PREIMAGE_LEN];
        let mut o = 0;
        out[o..o + MULTISIG_DOMAIN.len()].copy_from_slice(MULTISIG_DOMAIN);
        o += MULTISIG_DOMAIN.len();
        out[o..o + 20].copy_from_slice(&self.token_addr);
        o += 20;
        out[o] = self.n;
        o += 1;
        out[o] = self.k;
        o += 1;
        out[o..o + 32].copy_from_slice(&self.pubkey_root);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.salt);
        o += 32;
        debug_assert_eq!(o, PREIMAGE_LEN);
        out
    }

    /// SHA256(label_preimage).
    pub fn label_ref(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// Per §4.3: `nullifier_key = SHA256("anoma.multisig.v1.nfk-key" || label_preimage)`.
    pub fn nullifier_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_KEY_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }

    /// Per §4.3: `nullifierKeyCommitment = SHA256(nullifier_key)`.
    pub fn nullifier_key_commitment(&self) -> [u8; 32] {
        sha256(&self.nullifier_key())
    }
}

fn pubkey_root_of(sorted_pubkeys: &[[u8; 33]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for pk in sorted_pubkeys {
        hasher.update(pk);
    }
    hasher.finalize().into()
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 33] {
        let mut p = [byte; 33];
        p[0] = 0x02; // valid compressed prefix
        p
    }

    fn salt() -> [u8; 32] {
        [0xCD; 32]
    }

    #[test]
    fn encode_length_is_103() {
        let lp = LabelPreimage::new([0x11; 20], 2, &[pk(0x10), pk(0x20), pk(0x30)], salt()).unwrap();
        assert_eq!(lp.encode().len(), PREIMAGE_LEN);
        assert_eq!(PREIMAGE_LEN, 103);
    }

    #[test]
    fn encode_layout_matches_spec() {
        let lp = LabelPreimage::new([0xAA; 20], 1, &[pk(0x10)], salt()).unwrap();
        let enc = lp.encode();
        assert_eq!(&enc[..17], MULTISIG_DOMAIN);
        assert_eq!(&enc[17..37], &[0xAA; 20]);
        assert_eq!(enc[37], 1); // n
        assert_eq!(enc[38], 1); // k
        // pubkey_root at 39..71, salt at 71..103
        assert_eq!(&enc[71..103], &salt());
    }

    #[test]
    fn rejects_zero_salt() {
        let err = LabelPreimage::new([0; 20], 1, &[pk(0x10)], [0; 32]).unwrap_err();
        assert!(matches!(err, LabelError::ZeroSalt));
    }

    #[test]
    fn rejects_unsorted_pubkeys() {
        let err = LabelPreimage::new([0; 20], 1, &[pk(0x30), pk(0x10)], salt()).unwrap_err();
        assert!(matches!(err, LabelError::UnsortedPubkeys));
    }

    #[test]
    fn rejects_k_zero_and_k_gt_n() {
        let pks = [pk(0x10), pk(0x20)];
        assert!(matches!(
            LabelPreimage::new([0; 20], 0, &pks, salt()).unwrap_err(),
            LabelError::InvalidK { .. }
        ));
        assert!(matches!(
            LabelPreimage::new([0; 20], 3, &pks, salt()).unwrap_err(),
            LabelError::InvalidK { .. }
        ));
    }

    #[test]
    fn nullifier_key_chain_consistent() {
        let lp = LabelPreimage::new([0; 20], 1, &[pk(0x10)], salt()).unwrap();
        let k = lp.nullifier_key();
        let kc = lp.nullifier_key_commitment();
        assert_eq!(kc, sha256(&k));
    }
}
