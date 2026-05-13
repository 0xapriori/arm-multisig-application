//! `multisig_v1` RISC Zero guest. Dispatches between consumed/created branches based on the
//! shape of the witness blob (encoded via a tagged enum).

use multisig_core::constrain::{constrain_multisig_consumed, constrain_multisig_created};
use multisig_core::witness::MultisigBranchWitness;
use risc0_zkvm::guest::env;

/// Singleton `MultisigForwarder` address. PINNED — changing this changes the image ID, which
/// is the `logicRef` baked into vault notes (effectively a hard fork). Production deployment
/// should bake the real address before circuit compilation.
const MULTISIG_FORWARDER: [u8; 20] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
];

fn main() {
    let branch: MultisigBranchWitness = env::read();
    let journal = match branch {
        MultisigBranchWitness::Consumed(w) => {
            constrain_multisig_consumed(&w, MULTISIG_FORWARDER).expect("multisig consumed constraints failed")
        }
        MultisigBranchWitness::Created(w) => {
            constrain_multisig_created(&w).expect("multisig created constraints failed")
        }
    };
    env::commit_slice(&journal);
}
