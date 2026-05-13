//! Construction of the K-of-N signed `spend_message`.
//!
//! Per spec §5.3 step 11 (v0.4):
//!     spend_message = SHA256(
//!         "anoma.multisig.v1.spend"
//!      || consumed_vault.journal_digest
//!      || uint32_le(num_outflows)
//!      || sorted_ascending(outflow_journal_digests)
//!     )
//!
//! Sorting is lexicographic over the 32-byte digest, ascending. This is what binds the
//! K-of-N signature to every outflow's appData (and therefore every outflow's external
//! payload, including its forwarder/recipient/amount).

use sha2::{Digest, Sha256};

use crate::sig::K_DOMAIN_SEP;

/// Sorted set of outflow journal digests, ready to be folded into the spend message.
pub struct OutflowDigests(Vec<[u8; 32]>);

impl OutflowDigests {
    /// Take an arbitrary list of outflow journal digests, sort them ascending, and return the
    /// canonical ordering. Domain separation: the same set of digests in any input order
    /// produces the same canonical encoding, so the off-chain coordinator and the in-circuit
    /// witness assembly cannot disagree.
    pub fn new(mut digests: Vec<[u8; 32]>) -> Self {
        digests.sort();
        Self(digests)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub fn spend_message(consumed_journal_digest: &[u8; 32], outflows: &OutflowDigests) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(K_DOMAIN_SEP);
    hasher.update(consumed_journal_digest);
    let n = u32::try_from(outflows.len()).expect("more than u32::MAX outflows is impossible");
    hasher.update(n.to_le_bytes());
    for d in &outflows.0 {
        hasher.update(d);
    }
    hasher.finalize().into()
}

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
