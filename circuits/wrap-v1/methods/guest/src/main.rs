//! `wrap_v1` RISC Zero guest. Dispatches between inflow (consumed deposit ephemeral) and
//! outflow (created compliance-balance ephemeral) branches.

use multisig_core::constrain::{constrain_wrap_inflow, constrain_wrap_outflow};
use multisig_core::witness::WrapBranchWitness;
use risc0_zkvm::guest::env;

/// Singleton `WrapForwarder` address (deposits route here). Pinned at circuit-compile time.
const WRAP_FORWARDER: [u8; 20] = [
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
];

fn main() {
    let branch: WrapBranchWitness = env::read();
    let journal = match branch {
        WrapBranchWitness::Inflow(w) => {
            constrain_wrap_inflow(&w, WRAP_FORWARDER).expect("wrap_v1 inflow constraints failed")
        }
        WrapBranchWitness::Outflow(w) => {
            constrain_wrap_outflow(&w).expect("wrap_v1 outflow constraints failed")
        }
    };
    env::commit_slice(&journal);
}
