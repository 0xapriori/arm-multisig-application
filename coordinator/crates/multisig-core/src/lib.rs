//! Pure-Rust building blocks for the arm-multisig-application.
//!
//! Mirrors the on-chain Solidity types and the canonical RISC Zero journal encoding from
//! `anoma/pa-evm`'s `RiscZeroUtils.toJournal(Logic.Instance)`. Used by both the off-chain
//! coordinator and the in-circuit RISC Zero guest.
//!
//! Resource / NullifierKey / Digest types are sourced from `anoma-rm-risc0` v1.1.1 so the
//! commitment + nullifier formulas bind to Anoma's canonical compliance circuit.

pub mod constants;
pub mod journal;
pub mod label;
pub mod sig;
pub mod spend;
pub mod constrain;
pub mod witness;

pub use anoma_rm_risc0::{
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
pub use risc0_zkvm::sha::Digest;

pub use constants::{
    MULTISIG_FORWARDER_ADDRESS_LEN, WRAP_FORWARDER_ADDRESS_LEN, WRAP_FORWARDER_OP_WRAP,
};
pub use journal::{AppData, DeletionCriterion, ExpirableBlob, LogicInstance};
pub use label::{LabelPreimage, MULTISIG_DOMAIN, NULLIFIER_KEY_DOMAIN};
pub use sig::{verify_secp256k1, SigError, K_DOMAIN_SEP};
pub use spend::{spend_message, OutflowDigests};

pub use anoma_rm_risc0;
pub use risc0_zkvm;
