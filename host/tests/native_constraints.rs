//! Native (non-zkVM) tests of the constraint logic. These run instantly without invoking the
//! RISC Zero prover and exercise positive + negative paths for every multisig_v1 / wrap_v1
//! constraint.
//!
//! For end-to-end tests that actually generate and verify proofs, see `prove_and_verify.rs`.

use arm_multisig_host::fixtures::{
    build_full_spend_witness, encode_external_transfer, TEST_MULTISIG_FORWARDER, TEST_RECIPIENT,
    TEST_TOKEN,
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
    assert!(matches!(err, CircuitError::AmountSumMismatch { .. }), "got {err:?}");
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
    assert!(matches!(err, CircuitError::AmountSumMismatch { sum: 0, .. }), "got {err:?}");
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
