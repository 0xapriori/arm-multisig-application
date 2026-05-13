//! End-to-end RISC Zero proof generation + verification using the multisig_v1 guest.
//!
//! This test uses the real RISC Zero zkVM. It is slow (proof generation can take minutes).
//! Run with `RISC0_DEV_MODE=1` for fast iteration without real cryptographic proofs:
//!
//!     RISC0_DEV_MODE=1 cargo test -p arm-multisig-host --test prove_and_verify -- --nocapture
//!
//! Drop the env var to generate a real proof.

use arm_multisig_host::fixtures::build_full_spend_witness;
use multisig_v1::{prove_consumed, MULTISIG_V1_GUEST_ID};
use risc0_zkvm::ProverOpts;

#[test]
fn proves_and_verifies_full_spend() {
    let witness = build_full_spend_witness(7, 100);

    let receipt = prove_consumed(witness, ProverOpts::default()).expect("proving must succeed");

    receipt
        .verify(MULTISIG_V1_GUEST_ID)
        .expect("on-chain-equivalent verification must succeed");

    assert!(
        !receipt.journal.bytes.is_empty(),
        "journal should contain PA-format bytes"
    );

    eprintln!(
        "journal bytes (PA toJournal-equivalent): {} bytes — first 32 = {}",
        receipt.journal.bytes.len(),
        hex::encode(&receipt.journal.bytes[..32.min(receipt.journal.bytes.len())])
    );
}
