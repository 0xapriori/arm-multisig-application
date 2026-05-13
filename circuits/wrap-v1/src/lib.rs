//! Host-side facade for the `wrap_v1` RISC Zero guest.

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};
use thiserror::Error;

pub use multisig_core::witness::{WrapBranchWitness, WrapInflowWitness, WrapOutflowWitness};
pub use wrap_v1_methods::{WRAP_V1_GUEST_ELF, WRAP_V1_GUEST_ID};

#[derive(Debug, Error)]
pub enum ProveError {
    #[error("env build: {0}")]
    Env(String),
    #[error("prove: {0}")]
    Prove(String),
}

fn prove_branch(branch: &WrapBranchWitness, opts: ProverOpts) -> Result<Receipt, ProveError> {
    let env = ExecutorEnv::builder()
        .write(branch)
        .map_err(|e| ProveError::Env(e.to_string()))?
        .build()
        .map_err(|e| ProveError::Env(e.to_string()))?;
    Ok(default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), WRAP_V1_GUEST_ELF, &opts)
        .map_err(|e| ProveError::Prove(e.to_string()))?
        .receipt)
}

pub fn prove_inflow(witness: WrapInflowWitness, opts: ProverOpts) -> Result<Receipt, ProveError> {
    prove_branch(&WrapBranchWitness::Inflow(witness), opts)
}

pub fn prove_outflow(witness: WrapOutflowWitness, opts: ProverOpts) -> Result<Receipt, ProveError> {
    prove_branch(&WrapBranchWitness::Outflow(witness), opts)
}
