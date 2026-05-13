//! Construction of the K-of-N signed `spend_message`.
//!
//! Per spec §5.3 (v0.5):
//!     spend_message = SHA256(
//!         "anoma.multisig.v1.spend"
//!      || consumed_vault.journal_digest
//!      || uint32_le(num_recipients)
//!      || sorted_ascending(recipient_commitments)
//!     )
//!
//! - `consumed_vault.journal_digest` binds the entire consumed-vault appData (including any
//!   `externalPayload` blobs that authorize EVM-side `MultisigForwarder` transfers).
//! - The sorted recipient commitment list binds the K-of-N signature to the specific RM-
//!   internal recipients (cross-kind transfers to other vaults / AnomaPay users / etc.).
//!   For the pure EVM-withdraw case this list is empty and the signed message degrades to
//!   `SHA256(domain || journal_digest)` (matching v0.4 implementation).
//!
//! Sorting is lexicographic over the 32-byte commitment, ascending — domain-separates
//! from witness ordering and forces deterministic agreement between off-chain coordinator
//! and in-circuit witness assembly.

use sha2::{Digest, Sha256};

use crate::sig::K_DOMAIN_SEP;

/// Sorted set of recipient commitments, ready to be folded into the spend message.
/// (Pre-v0.5 this was named `OutflowDigests`; renamed for clarity since recipients are now
/// bound by their commitment, not by their outflow journal digest.)
pub struct RecipientCommitments(Vec<[u8; 32]>);

impl RecipientCommitments {
    /// Take an arbitrary list of recipient commitments, sort them ascending, and return the
    /// canonical ordering.
    pub fn new(mut commitments: Vec<[u8; 32]>) -> Self {
        commitments.sort();
        Self(commitments)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// v0.5 spend_message constructor. `recipients` is the sorted set of RM-internal recipient
/// commitments; pass an empty `RecipientCommitments::new(vec![])` for pure EVM-withdraw mode.
pub fn spend_message(consumed_journal_digest: &[u8; 32], recipients: &RecipientCommitments) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(K_DOMAIN_SEP);
    hasher.update(consumed_journal_digest);
    let n = u32::try_from(recipients.len()).expect("more than u32::MAX recipients is impossible");
    hasher.update(n.to_le_bytes());
    for c in &recipients.0 {
        hasher.update(c);
    }
    hasher.finalize().into()
}

/// Backwards-compat alias kept for one release so existing call sites compile during migration.
#[deprecated(note = "renamed to RecipientCommitments in v0.5")]
pub type OutflowDigests = RecipientCommitments;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_under_input_reordering() {
        let consumed = [0x11; 32];
        let a = OutflowDigests::new(vec![[0xCC; 32], [0xAA; 32], [0xBB; 32]]);
        let b = OutflowDigests::new(vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]]);
        assert_eq!(spend_message(&consumed, &a), spend_message(&consumed, &b));
    }

    #[test]
    fn no_outflows_still_well_defined() {
        let consumed = [0x11; 32];
        let _ = spend_message(&consumed, &OutflowDigests::new(vec![]));
    }

    #[test]
    fn changes_with_consumed_digest() {
        let outflows = OutflowDigests::new(vec![[0xAA; 32]]);
        let m1 = spend_message(&[0x01; 32], &outflows);
        let m2 = spend_message(&[0x02; 32], &outflows);
        assert_ne!(m1, m2);
    }

    #[test]
    fn changes_when_outflow_added() {
        let consumed = [0x11; 32];
        let m1 = spend_message(&consumed, &OutflowDigests::new(vec![[0xAA; 32]]));
        let m2 = spend_message(&consumed, &OutflowDigests::new(vec![[0xAA; 32], [0xBB; 32]]));
        assert_ne!(m1, m2);
    }
}
