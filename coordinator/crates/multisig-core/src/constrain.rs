//! Pure constraint logic — what each circuit branch enforces.
//!
//! Each `constrain_*` function takes a witness + the canonical `MULTISIG_FORWARDER` /
//! `WRAP_FORWARDER` addresses (compile-time constants for the deployed system) and returns
//! the journal bytes to commit (matching `pa-evm`'s `RiscZeroUtils.toJournal(Logic.Instance)`
//! byte-for-byte).
//!
//! The same code runs natively in tests AND inside the RISC Zero zkVM guest (via
//! `env::commit_slice(&result?)`).

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::constants::{MULTISIG_FORWARDER_ADDRESS_LEN, WRAP_FORWARDER_OP_WRAP};
use crate::journal::{self, LogicInstance};
use crate::label::{LabelPreimage, NULLIFIER_KEY_DOMAIN};
use crate::sig::{verify_secp256k1, SigError};
use crate::spend::{spend_message, OutflowDigests};
use crate::witness::{
    MultisigConsumedWitness, MultisigCreatedWitness, WrapInflowWitness, WrapOutflowWitness,
};

use risc0_zkvm::sha::Digest;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("nullifier key bytes do not match SHA256(domain || label_preimage)")]
    WrongNullifierKey,
    #[error("nf_key.commit() != resource.nk_commitment")]
    WrongNullifierKeyCommitment,
    #[error("SHA256(label_preimage) != resource.label_ref")]
    WrongLabelRef,
    #[error("pubkey count != label_preimage.n")]
    PubkeyCountMismatch,
    #[error("pubkeys not strictly sorted ascending")]
    UnsortedPubkeys,
    #[error("SHA256(concat(pubkeys)) != label_preimage.pubkey_root")]
    WrongPubkeyRoot,
    #[error("signature count != label_preimage.k")]
    WrongSignerCount,
    #[error("signer indices not strictly increasing or out of range")]
    BadSignerIndices,
    #[error("change_resource.label_ref != consumed.label_ref")]
    ChangeLabelMismatch,
    #[error("change_resource.quantity > consumed.quantity")]
    ChangeOverflow,
    #[error("change_resource.commitment not in action_tags")]
    ChangeNotInAction,
    #[error("external payload[{idx}] is malformed")]
    BadExternalPayload { idx: usize },
    #[error("external payload[{idx}] token != label.token_addr")]
    ExternalTokenMismatch { idx: usize },
    #[error("sum(MULTISIG_FORWARDER amounts) != consumed - change ({sum} vs {expected})")]
    AmountSumMismatch { sum: u128, expected: u128 },
    #[error("WrapForwarder external_payload op != WRAP")]
    WrapInflowWrongOp,
    #[error("WrapForwarder external_payload token != label.token_addr")]
    WrapInflowTokenMismatch,
    #[error("WrapForwarder external_payload amount != paired_vault_quantity")]
    WrapInflowAmountMismatch,
    #[error("WrapForwarder external_payload depositor != witness depositor")]
    WrapInflowDepositorMismatch,
    #[error("inflow ephemeral must have ephemeral=true")]
    InflowMustBeEphemeral,
    #[error("outflow ephemeral must have ephemeral=true")]
    OutflowMustBeEphemeral,
    #[error("outflow label_preimage hash != resource.label_ref")]
    OutflowLabelMismatch,
    #[error("salt must be non-zero (created branch)")]
    ZeroSalt,
    #[error("k must be 1..=n; n must be 1..=32")]
    InvalidKN,
    #[error("expected exactly 1 inflow externalPayload blob, got {got}")]
    WrongInflowPayloadCount { got: usize },
    #[error("signature failed: {0:?}")]
    SignatureError(SigError),
    #[error("anoma resource error")]
    ResourceError,
}

impl From<SigError> for CircuitError {
    fn from(e: SigError) -> Self {
        CircuitError::SignatureError(e)
    }
}

// =============================================================================================
// multisig_v1 — consumed branch
// =============================================================================================

/// Verify a vault-spend authorization. Returns the PA-format journal bytes to commit.
///
/// Spec §5.3 (v0.5 refinement of v0.4): the external_payload lives on the CONSUMED vault note
/// (not on the outflow ephemeral). The K-of-N signature binds to the consumed journal_digest,
/// which already commits to all external transfers. Outflow ephemerals are pure compliance
/// bookkeeping (`wrap_v1` outflow branch is trivial). The amount-binding constraint is that
/// `sum(external_payload amounts to MULTISIG_FORWARDER) == consumed.quantity - change.quantity`.
pub fn constrain_multisig_consumed(
    witness: &MultisigConsumedWitness,
    multisig_forwarder: [u8; MULTISIG_FORWARDER_ADDRESS_LEN],
) -> Result<Vec<u8>, CircuitError> {
    // 1. Verify nullifier key derivation: nf_key bytes == SHA256(domain || label_preimage)
    let expected_nf_key_bytes = derive_nullifier_key_bytes(&witness.label_preimage);
    if witness.nf_key.inner() != expected_nf_key_bytes {
        return Err(CircuitError::WrongNullifierKey);
    }

    // 2. Verify nf_key.commit() == resource.nk_commitment
    if witness.nf_key.commit() != witness.resource.nk_commitment {
        return Err(CircuitError::WrongNullifierKeyCommitment);
    }

    // 3. Verify SHA256(label_preimage) == resource.label_ref
    let expected_label_ref = witness.label_preimage.label_ref();
    if witness.resource.label_ref.as_bytes() != expected_label_ref {
        return Err(CircuitError::WrongLabelRef);
    }

    // 4. Verify pubkey count, sortedness, root
    let n = witness.label_preimage.n as usize;
    if witness.pubkeys.len() != n {
        return Err(CircuitError::PubkeyCountMismatch);
    }
    for w in witness.pubkeys.windows(2) {
        if w[0] >= w[1] {
            return Err(CircuitError::UnsortedPubkeys);
        }
    }
    let mut hasher = Sha256::new();
    for pk in &witness.pubkeys {
        hasher.update(pk);
    }
    let computed_root: [u8; 32] = hasher.finalize().into();
    if computed_root != witness.label_preimage.pubkey_root {
        return Err(CircuitError::WrongPubkeyRoot);
    }

    // 5. Verify k_witness == label_preimage.k
    if witness.signatures.len() != witness.label_preimage.k as usize {
        return Err(CircuitError::WrongSignerCount);
    }

    // 6. Verify signer indices are strictly increasing and in-range
    let mut prev: Option<u32> = None;
    for slot in &witness.signatures {
        if slot.idx as usize >= n {
            return Err(CircuitError::BadSignerIndices);
        }
        if let Some(p) = prev {
            if p >= slot.idx {
                return Err(CircuitError::BadSignerIndices);
            }
        }
        prev = Some(slot.idx);
    }

    // 7. Verify change resource is the same kind (vault) and quantity ≤ consumed
    if witness.change_resource.label_ref != witness.resource.label_ref {
        return Err(CircuitError::ChangeLabelMismatch);
    }
    if witness.change_resource.quantity > witness.resource.quantity {
        return Err(CircuitError::ChangeOverflow);
    }

    // 8. Verify change.commitment is in the witnessed action_tags (sanity that the change
    //    referenced exists in the action). PA's overall lookup-by-tag binds the witnessed
    //    action_tags to actual logic verifier inputs.
    let change_commitment = witness.change_resource.commitment();
    if !witness.action_tags.iter().any(|t| t == &change_commitment) {
        return Err(CircuitError::ChangeNotInAction);
    }

    // 9. Compute spent_amount = consumed - change
    let spent_amount = witness.resource.quantity - witness.change_resource.quantity;

    // 10. Walk external payloads; for each MULTISIG_FORWARDER call, accumulate the (token,
    //     amount) and require token == label.token_addr.
    let mut sum: u128 = 0;
    for (idx, blob) in witness.app_data.external_payload.iter().enumerate() {
        let parsed = parse_external_call(&blob.blob).ok_or(CircuitError::BadExternalPayload { idx })?;
        if parsed.forwarder == multisig_forwarder {
            // Decode the inner input as (token, recipient, amount, expected)
            let inner = parse_multisig_call_input(&parsed.input)
                .ok_or(CircuitError::BadExternalPayload { idx })?;
            if inner.token != witness.label_preimage.token_addr {
                return Err(CircuitError::ExternalTokenMismatch { idx });
            }
            sum = sum
                .checked_add(inner.amount)
                .ok_or(CircuitError::AmountSumMismatch { sum: u128::MAX, expected: spent_amount })?;
        }
    }
    if sum != spent_amount {
        return Err(CircuitError::AmountSumMismatch {
            sum,
            expected: spent_amount,
        });
    }

    // 11. Compute the consumed vault's logic instance journal (PA-format).
    let tag = witness.resource.tag(true, &witness.nf_key).map_err(|_| CircuitError::ResourceError)?;
    let instance = LogicInstance {
        tag: digest_to_array(&tag),
        is_consumed: true,
        action_tree_root: digest_to_array(&witness.action_tree_root),
        app_data: witness.app_data.clone(),
    };
    let journal_bytes = journal::encode(&instance);
    let journal_digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&journal_bytes);
        h.finalize().into()
    };

    // 12. spend_message = SHA256(domain || journal_digest). For v0.5 we no longer fold in
    //     outflow_journal_digests because external_payload sits on the consumed vault and is
    //     therefore already covered by `journal_digest`.
    let spend_msg = spend_message(&journal_digest, &OutflowDigests::new(vec![]));

    // 13. Verify all K signatures
    for slot in &witness.signatures {
        let pk = &witness.pubkeys[slot.idx as usize];
        verify_secp256k1(pk, &spend_msg, &slot.sig_der)?;
    }

    Ok(journal_bytes)
}

// =============================================================================================
// multisig_v1 — created branch
// =============================================================================================

/// Verify a fresh vault-note minting. Returns PA-format journal bytes.
pub fn constrain_multisig_created(
    witness: &MultisigCreatedWitness,
) -> Result<Vec<u8>, CircuitError> {
    // 1. salt != 0
    if witness.label_preimage.salt == [0u8; 32] {
        return Err(CircuitError::ZeroSalt);
    }
    // 2. 1 <= k <= n <= 32
    let n = witness.label_preimage.n;
    let k = witness.label_preimage.k;
    if !(1..=32).contains(&n) || k == 0 || k > n {
        return Err(CircuitError::InvalidKN);
    }
    // 3. SHA256(label_preimage) == resource.label_ref
    let expected_label_ref = witness.label_preimage.label_ref();
    if witness.resource.label_ref.as_bytes() != expected_label_ref {
        return Err(CircuitError::WrongLabelRef);
    }

    // 4. Build the journal (tag = commitment, is_consumed = false)
    let tag = witness.resource.commitment();
    let instance = LogicInstance {
        tag: digest_to_array(&tag),
        is_consumed: false,
        action_tree_root: digest_to_array(&witness.action_tree_root),
        app_data: witness.app_data.clone(),
    };
    Ok(journal::encode(&instance))
}

// =============================================================================================
// wrap_v1 — inflow branch
// =============================================================================================

pub fn constrain_wrap_inflow(
    witness: &WrapInflowWitness,
    wrap_forwarder: [u8; MULTISIG_FORWARDER_ADDRESS_LEN],
) -> Result<Vec<u8>, CircuitError> {
    // 1. Inflow must be ephemeral
    if !witness.resource.is_ephemeral {
        return Err(CircuitError::InflowMustBeEphemeral);
    }
    // 2. Verify nullifier key derivation (vs paired vault note's label) — for an inflow,
    //    the nf_key isn't security-critical (no auth tied to inflows) but consistency makes
    //    the action shape predictable.
    let expected_nf_key_bytes = derive_nullifier_key_bytes(&witness.paired_vault_label_preimage);
    if witness.nf_key.inner() != expected_nf_key_bytes {
        return Err(CircuitError::WrongNullifierKey);
    }
    if witness.nf_key.commit() != witness.resource.nk_commitment {
        return Err(CircuitError::WrongNullifierKeyCommitment);
    }
    // 3. label_ref of inflow == labelRef of paired vault
    let expected_label_ref = witness.paired_vault_label_preimage.label_ref();
    if witness.resource.label_ref.as_bytes() != expected_label_ref {
        return Err(CircuitError::WrongLabelRef);
    }
    // 4. external_payload — exactly one blob, decoded as (forwarder, input, expected)
    if witness.app_data.external_payload.len() != 1 {
        return Err(CircuitError::WrongInflowPayloadCount {
            got: witness.app_data.external_payload.len(),
        });
    }
    let blob = &witness.app_data.external_payload[0].blob;
    let parsed = parse_external_call(blob).ok_or(CircuitError::BadExternalPayload { idx: 0 })?;
    if parsed.forwarder != wrap_forwarder {
        return Err(CircuitError::BadExternalPayload { idx: 0 });
    }
    let inner = parse_wrap_call_input(&parsed.input).ok_or(CircuitError::BadExternalPayload { idx: 0 })?;
    if inner.op != WRAP_FORWARDER_OP_WRAP {
        return Err(CircuitError::WrapInflowWrongOp);
    }
    if inner.token != witness.paired_vault_label_preimage.token_addr {
        return Err(CircuitError::WrapInflowTokenMismatch);
    }
    if inner.amount != witness.paired_vault_quantity {
        return Err(CircuitError::WrapInflowAmountMismatch);
    }
    if inner.from != witness.depositor {
        return Err(CircuitError::WrapInflowDepositorMismatch);
    }

    // 5. Build journal
    let tag = witness.resource.tag(true, &witness.nf_key).map_err(|_| CircuitError::ResourceError)?;
    let instance = LogicInstance {
        tag: digest_to_array(&tag),
        is_consumed: true,
        action_tree_root: digest_to_array(&witness.action_tree_root),
        app_data: witness.app_data.clone(),
    };
    Ok(journal::encode(&instance))
}

// =============================================================================================
// wrap_v1 — outflow branch
// =============================================================================================

pub fn constrain_wrap_outflow(witness: &WrapOutflowWitness) -> Result<Vec<u8>, CircuitError> {
    // 1. Must be ephemeral
    if !witness.resource.is_ephemeral {
        return Err(CircuitError::OutflowMustBeEphemeral);
    }
    // 2. label_preimage matches resource.label_ref
    let expected_label_ref = witness.label_preimage.label_ref();
    if witness.resource.label_ref.as_bytes() != expected_label_ref {
        return Err(CircuitError::OutflowLabelMismatch);
    }

    // 3. Build journal (tag = commitment, is_consumed = false — outflow is created)
    let tag = witness.resource.commitment();
    let instance = LogicInstance {
        tag: digest_to_array(&tag),
        is_consumed: false,
        action_tree_root: digest_to_array(&witness.action_tree_root),
        app_data: witness.app_data.clone(),
    };
    Ok(journal::encode(&instance))
}

// =============================================================================================
// Helpers
// =============================================================================================

/// `nullifier_key = SHA256("anoma.multisig.v1.nfk-key" ‖ label_preimage)` per spec §4.3.
/// Returns the 32 raw bytes that will be wrapped into `NullifierKey::from_bytes`.
fn derive_nullifier_key_bytes(label: &LabelPreimage) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULLIFIER_KEY_DOMAIN);
    h.update(label.encode());
    h.finalize().into()
}

fn digest_to_array(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// External payload blob layout: solidity `abi.encode(address forwarder, bytes input, bytes expected)`.
///
/// abi.encode of `(address, bytes, bytes)` produces:
///   word 0  (32B): forwarder address (left-padded to 32)
///   word 1  (32B): offset to `input` bytes data (= 0x60 = 96)
///   word 2  (32B): offset to `expected` bytes data
///   ... input length (32B) ... input data (padded to 32B multiples) ...
///   ... expected length (32B) ... expected data ...
///
/// We parse this layout. Returns None on malformed input.
struct ParsedExternalCall<'a> {
    forwarder: [u8; 20],
    input: &'a [u8],
    #[allow(dead_code)]
    expected: &'a [u8],
}

fn parse_external_call(blob: &[u8]) -> Option<ParsedExternalCall<'_>> {
    if blob.len() < 96 {
        return None;
    }
    // word 0: address (right-aligned in 32 bytes)
    let mut forwarder = [0u8; 20];
    forwarder.copy_from_slice(&blob[12..32]);
    // word 1: offset to input
    let input_off = read_uint256(&blob[32..64])? as usize;
    // word 2: offset to expected
    let expected_off = read_uint256(&blob[64..96])? as usize;

    // Decode the bytes blobs at the given offsets
    let input = read_bytes(blob, input_off)?;
    let expected = read_bytes(blob, expected_off)?;

    Some(ParsedExternalCall {
        forwarder,
        input,
        expected,
    })
}

fn read_uint256(slice: &[u8]) -> Option<u128> {
    if slice.len() < 32 {
        return None;
    }
    // Top 16 bytes must be zero (we constrain inputs to fit u128 for amounts; offsets/lengths
    // also fit easily).
    if slice[..16] != [0u8; 16] {
        return None;
    }
    Some(u128::from_be_bytes(slice[16..32].try_into().ok()?))
}

fn read_bytes(blob: &[u8], offset: usize) -> Option<&[u8]> {
    if offset + 32 > blob.len() {
        return None;
    }
    let len = read_uint256(&blob[offset..offset + 32])? as usize;
    let data_start = offset + 32;
    let data_end = data_start.checked_add(len)?;
    if data_end > blob.len() {
        return None;
    }
    Some(&blob[data_start..data_end])
}

/// Inner input for MultisigForwarder calls: `abi.encode(address token, address to, uint256 amount, bytes expected)`.
struct MultisigInput<'a> {
    token: [u8; 20],
    #[allow(dead_code)]
    recipient: [u8; 20],
    amount: u128,
    #[allow(dead_code)]
    expected: &'a [u8],
}

fn parse_multisig_call_input(input: &[u8]) -> Option<MultisigInput<'_>> {
    if input.len() < 128 {
        return None;
    }
    let mut token = [0u8; 20];
    token.copy_from_slice(&input[12..32]);
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&input[32 + 12..64]);
    let amount = read_uint256(&input[64..96])?;
    let expected_off = read_uint256(&input[96..128])? as usize;
    let expected = read_bytes(input, expected_off)?;
    Some(MultisigInput {
        token,
        recipient,
        amount,
        expected,
    })
}

/// Inner input for WrapForwarder calls: `abi.encode(Op op, address token, address from, uint256 amount, bytes expected)`.
/// Op is encoded as uint8 → uint256.
struct WrapInput<'a> {
    op: u8,
    token: [u8; 20],
    from: [u8; 20],
    amount: u128,
    #[allow(dead_code)]
    expected: &'a [u8],
}

fn parse_wrap_call_input(input: &[u8]) -> Option<WrapInput<'_>> {
    if input.len() < 160 {
        return None;
    }
    // word 0: Op (uint8 in u256, value at byte 31)
    let op_word = &input[0..32];
    if op_word[..31] != [0u8; 31] {
        return None;
    }
    let op = op_word[31];
    let mut token = [0u8; 20];
    token.copy_from_slice(&input[32 + 12..64]);
    let mut from = [0u8; 20];
    from.copy_from_slice(&input[64 + 12..96]);
    let amount = read_uint256(&input[96..128])?;
    let expected_off = read_uint256(&input[128..160])? as usize;
    let expected = read_bytes(input, expected_off)?;
    Some(WrapInput {
        op,
        token,
        from,
        amount,
        expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{DeletionCriterion, ExpirableBlob};

    /// Build an abi.encode(address, bytes, bytes) blob for testing.
    pub(crate) fn abi_encode_external_call(
        forwarder: [u8; 20],
        input: &[u8],
        expected: &[u8],
    ) -> Vec<u8> {
        let pad = |b: &[u8]| {
            let mut v = b.to_vec();
            let rem = v.len() % 32;
            if rem != 0 {
                v.extend(std::iter::repeat(0u8).take(32 - rem));
            }
            v
        };
        let input_len_word = u256_be(input.len() as u128);
        let expected_len_word = u256_be(expected.len() as u128);

        let mut out = Vec::new();
        // word 0: address (right-aligned)
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&forwarder);
        // word 1: offset to input = 0x60
        out.extend_from_slice(&u256_be(0x60));
        // word 2: offset to expected = 0x60 + 32 + padded(input)
        let padded_input = pad(input);
        let expected_offset = 0x60u128 + 32 + padded_input.len() as u128;
        out.extend_from_slice(&u256_be(expected_offset));
        // input section: length + padded data
        out.extend_from_slice(&input_len_word);
        out.extend_from_slice(&padded_input);
        // expected section: length + padded data
        out.extend_from_slice(&expected_len_word);
        out.extend_from_slice(&pad(expected));
        out
    }

    pub(crate) fn abi_encode_multisig_input(
        token: [u8; 20],
        recipient: [u8; 20],
        amount: u128,
        expected: &[u8],
    ) -> Vec<u8> {
        let pad = |b: &[u8]| {
            let mut v = b.to_vec();
            let rem = v.len() % 32;
            if rem != 0 {
                v.extend(std::iter::repeat(0u8).take(32 - rem));
            }
            v
        };
        let mut out = Vec::new();
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&token);
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&recipient);
        out.extend_from_slice(&u256_be(amount));
        // expected offset = 4 * 32 = 128
        out.extend_from_slice(&u256_be(128));
        out.extend_from_slice(&u256_be(expected.len() as u128));
        out.extend_from_slice(&pad(expected));
        out
    }

    pub(crate) fn u256_be(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&v.to_be_bytes());
        out
    }

    #[test]
    fn parse_external_call_round_trip() {
        let fwd = [0xAB; 20];
        let inner = vec![0x11, 0x22, 0x33, 0x44, 0x55];
        let expected = vec![0x99];
        let blob = abi_encode_external_call(fwd, &inner, &expected);
        let parsed = parse_external_call(&blob).expect("parse");
        assert_eq!(parsed.forwarder, fwd);
        assert_eq!(parsed.input, &inner[..]);
        assert_eq!(parsed.expected, &expected[..]);
    }

    #[test]
    fn parse_multisig_input_round_trip() {
        let token = [0xCC; 20];
        let recipient = [0xDD; 20];
        let amount = 12345u128;
        let expected = vec![0x01];
        let blob = abi_encode_multisig_input(token, recipient, amount, &expected);
        let parsed = parse_multisig_call_input(&blob).expect("parse");
        assert_eq!(parsed.token, token);
        assert_eq!(parsed.recipient, recipient);
        assert_eq!(parsed.amount, amount);
        assert_eq!(parsed.expected, &expected[..]);
    }

    #[test]
    fn _exports_used() {
        // Avoid unused-import warning on the helpers in test mode.
        let _ = ExpirableBlob {
            deletion_criterion: DeletionCriterion::Never,
            blob: vec![],
        };
    }
}
