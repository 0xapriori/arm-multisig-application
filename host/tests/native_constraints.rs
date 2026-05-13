//! Native (non-zkVM) tests of the constraint logic. These run instantly without invoking the
//! RISC Zero prover and exercise positive + negative paths for every multisig_v1 / wrap_v1
//! constraint.
//!
//! For end-to-end tests that actually generate and verify proofs, see `prove_and_verify.rs`.

use arm_multisig_host::fixtures::{
    build_full_spend_witness, build_hybrid_witness, build_rm_internal_witness, encode_external_transfer,
    TEST_MULTISIG_FORWARDER, TEST_RECIPIENT, TEST_TOKEN,
};
use multisig_core::constrain::{constrain_multisig_consumed, CircuitError};
use multisig_core::journal::{DeletionCriterion, ExpirableBlob};

#[test]
fn happy_path_full_spend() {
    let witness = build_full_spend_witness(7, 100);
    let journal = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect("constraints pass");
    assert!(journal.len() >= 32 + 4 + 32 + 16, "journal must be at least the empty-appData size");
}

#[test]
fn rejects_amount_mismatch() {
    let mut witness = build_full_spend_witness(7, 100);
    // Tamper with the external payload to claim a different amount than vault.quantity - change.quantity
    let bad_blob = encode_external_transfer(TEST_MULTISIG_FORWARDER, TEST_TOKEN, TEST_RECIPIENT, 99);
    witness.app_data.external_payload = vec![ExpirableBlob {
        deletion_criterion: DeletionCriterion::Never,
        blob: bad_blob,
    }];
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ConservationBroken { .. }), "got {err:?}");
}

#[test]
fn rejects_wrong_token() {
    let mut witness = build_full_spend_witness(7, 100);
    let wrong_token = [0xCC; 20];
    let bad_blob = encode_external_transfer(TEST_MULTISIG_FORWARDER, wrong_token, TEST_RECIPIENT, 100);
    witness.app_data.external_payload = vec![ExpirableBlob {
        deletion_criterion: DeletionCriterion::Never,
        blob: bad_blob,
    }];
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ExternalTokenMismatch { .. }), "got {err:?}");
}

#[test]
fn rejects_non_canonical_forwarder_silently_skips_amount() {
    // External call to a non-MULTISIG_FORWARDER address: our constraint only sums amounts
    // for the canonical forwarder. So an external call to some other address is allowed by
    // the multisig logic (whatever forwarder is being called handles its own auth). But the
    // sum-binding for MULTISIG_FORWARDER is now zero, while consumed - change = 100, so the
    // constraint fails.
    let mut witness = build_full_spend_witness(7, 100);
    let other_fwd = [0xDD; 20];
    let bad_blob = encode_external_transfer(other_fwd, TEST_TOKEN, TEST_RECIPIENT, 100);
    witness.app_data.external_payload = vec![ExpirableBlob {
        deletion_criterion: DeletionCriterion::Never,
        blob: bad_blob,
    }];
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ConservationBroken { external_sum: 0, .. }), "got {err:?}");
}

#[test]
fn rejects_signature_tampering() {
    let mut witness = build_full_spend_witness(7, 100);
    // Flip a byte in one signature
    let sig = &mut witness.signatures[0].sig_der;
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::SignatureError(_)), "got {err:?}");
}

#[test]
fn rejects_duplicate_signer_index() {
    let mut witness = build_full_spend_witness(7, 100);
    // Force both signatures to use index 0 (duplicate signer)
    let sig0 = witness.signatures[0].sig_der.clone();
    witness.signatures[1].idx = 0;
    witness.signatures[1].sig_der = sig0;
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::BadSignerIndices), "got {err:?}");
}

#[test]
fn rejects_change_with_different_label() {
    let mut witness = build_full_spend_witness(7, 100);
    // Mutate the change resource's label to a different vault's labelRef
    let mut other_label_bytes = [0u8; 32];
    other_label_bytes[0] = 0xFF;
    witness.change_resource.label_ref = risc0_zkvm::sha::Digest::from_bytes(other_label_bytes);
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ChangeLabelMismatch), "got {err:?}");
}

#[test]
fn rejects_change_overflow() {
    // change.quantity > consumed.quantity should error
    let mut witness = build_full_spend_witness(7, 100);
    witness.change_resource.quantity = 200;
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ChangeOverflow), "got {err:?}");
}

#[test]
fn rejects_change_not_in_action() {
    // Change present in witness but not registered in action_tags
    let mut witness = build_full_spend_witness(7, 100);
    witness.action_tags.pop(); // drop change commitment from action_tags
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ChangeNotInAction), "got {err:?}");
}

// ---------------------------------------------------------------------------
// v0.5: RM-internal transfer mode (the AnomaPay-style private-transfer path).
// No EVM crossing — recipient resource is created in the RM directly.
// ---------------------------------------------------------------------------

#[test]
fn rm_internal_full_transfer() {
    // Consume 100 vault-A; transfer 100 to recipient (different vault); change = 0.
    // No external_payload — PA only sees commitment updates. Recipient + amount
    // are NOT public on chain.
    let witness = build_rm_internal_witness(7, 42, 100, 100);
    let journal = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect("must pass");
    assert!(!journal.is_empty());
    // The journal's appData section should encode an empty externalPayload list (4-byte
    // little-endian zero at the externalPayload-length offset).
    // Layout: tag(32) + isConsumed(4) + actionTreeRoot(32) + 4 length-prefixed payload arrays.
    // For empty appData all four length prefixes are zero (16 bytes total).
    assert_eq!(&journal[68..84], &[0u8; 16], "all four payload arrays should be empty");
}

#[test]
fn rm_internal_partial_transfer_with_change() {
    // Consume 100; transfer 30 to recipient; 70 stays as change in vault A.
    let witness = build_rm_internal_witness(7, 42, 100, 30);
    let _ = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect("must pass");
}

#[test]
fn hybrid_rm_internal_plus_evm_withdraw() {
    // Consume 100; 30 to recipient (RM-internal, private), 50 to EVM address (public),
    // 20 stays as change.
    let witness = build_hybrid_witness(7, 42, 100, 30, 50);
    let _ = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect("must pass");
}

#[test]
fn rejects_recipient_swap_after_signing() {
    // Build a valid RM-internal witness, then swap the recipient resource for one with a
    // different commitment. The K-of-N signature was bound to the original recipient's
    // commitment via spend_message — verification must fail.
    let mut witness = build_rm_internal_witness(7, 42, 100, 100);

    // Replace the recipient with a different one (different vault entirely)
    let other_vault = arm_multisig_host::fixtures::TestVault::deterministic(99);
    let mut other_nonce = [0u8; 32];
    other_nonce[0] = 0xEE;
    let mut other_seed = [0u8; 32];
    other_seed[0] = 0xFE;
    let new_recipient = other_vault.build_resource(100, other_nonce, other_seed);

    // Update action_tags to include the substituted commitment so the in-action check passes
    witness.action_tags.pop();
    witness.action_tags.push(new_recipient.commitment());
    witness.recipient_resources = vec![new_recipient];

    // Signature was over the OLD recipient's commitment; new spend_message differs; sigs fail.
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::SignatureError(_)), "got {err:?}");
}

#[test]
fn rejects_recipient_not_in_action() {
    // Recipient witnessed but its commitment isn't registered in action_tags.
    let mut witness = build_rm_internal_witness(7, 42, 100, 100);
    witness.action_tags.pop(); // drop the recipient commitment
    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::RecipientNotInAction { .. }), "got {err:?}");
}

#[test]
fn rejects_conservation_break_in_rm_internal() {
    // Build a witness where consumed=100 but change(60) + recipient(50) + external(0) = 110.
    // Signers approve the (bad) sums; the circuit must reject. We construct from scratch
    // because mutating any quantity post-build invalidates the commitment-in-action_tags
    // check, which would fire before conservation. The constructor below is a thin
    // shadow of build_rm_internal_witness with explicit change quantity.
    use arm_multisig_host::fixtures::{compute_spend_message, sign_low_s_der, TestVault};
    use multisig_core::journal::AppData;
    use multisig_core::witness::{MultisigConsumedWitness, SignerSlot};
    use sha2::{Digest as _, Sha256};

    let vault = TestVault::deterministic(7);
    let recipient_vault = TestVault::deterministic(42);

    let mut nonce = [0u8; 32]; nonce[0] = 0xCA;
    let mut rand_seed = [0u8; 32]; rand_seed[0] = 0xFE;
    let resource = vault.build_resource(100, nonce, rand_seed);

    let mut change_nonce = [0u8; 32]; change_nonce[0] = 0xCC;
    let change_resource = vault.build_resource(60, change_nonce, rand_seed);  // 60 instead of 50

    let mut recipient_nonce = [0u8; 32]; recipient_nonce[0] = 0xDD;
    let recipient_resource = recipient_vault.build_resource(50, recipient_nonce, rand_seed);

    let tag = resource.tag(true, &vault.nf_key).expect("tag");
    let action_tags = vec![tag, change_resource.commitment(), recipient_resource.commitment()];
    let mut h = Sha256::new();
    for t in &action_tags { h.update(t.as_bytes()); }
    let atr_bytes: [u8; 32] = h.finalize().into();

    let mut witness = MultisigConsumedWitness {
        action_tree_root: risc0_zkvm::sha::Digest::from_bytes(atr_bytes),
        app_data: AppData::default(),
        resource,
        nf_key: vault.nf_key.clone(),
        label_preimage: vault.label.clone(),
        pubkeys: vault.pubkeys.clone(),
        signatures: vec![],
        change_resource,
        recipient_resources: vec![recipient_resource],
        action_tags,
    };
    let msg = compute_spend_message(&witness);
    witness.signatures = vec![
        SignerSlot { idx: 0, sig_der: sign_low_s_der(&vault.signers[0], &msg) },
        SignerSlot { idx: 2, sig_der: sign_low_s_der(&vault.signers[2], &msg) },
    ];

    let err = constrain_multisig_consumed(&witness, TEST_MULTISIG_FORWARDER).expect_err("must fail");
    assert!(matches!(err, CircuitError::ConservationBroken { .. }), "got {err:?}");
}
