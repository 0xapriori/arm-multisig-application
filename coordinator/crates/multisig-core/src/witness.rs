//! Witness types read by the RISC Zero guests via `env::read()`.
//!
//! Each branch (consumed/created × multisig/wrap) has its own witness struct. All carry the
//! private inputs needed to satisfy the constraints in `crate::constrain`, plus the public
//! inputs (action_tree_root, app_data) that mirror what PA passes to verification.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::journal::AppData;
use crate::label::LabelPreimage;
use anoma_rm_risc0::{nullifier_key::NullifierKey, resource::Resource};
use risc0_zkvm::sha::Digest;

/// One slot in the K-of-N signed authorization. `idx` is the position into the sorted pubkey
/// array; signatures across the K slots must have strictly-increasing indices (enforces
/// distinct signers).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerSlot {
    pub idx: u32,
    /// DER-encoded ECDSA secp256k1 signature, low-s.
    pub sig_der: Vec<u8>,
}

/// Witness for `multisig_v1` consumed branch (a vault note being spent).
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct MultisigConsumedWitness {
    /// Public input mirror — `Logic.Instance.actionTreeRoot`.
    pub action_tree_root: Digest,
    /// Public input mirror — `Logic.Instance.appData`. Contains the `externalPayload` blobs
    /// that bind the K-of-N signature to the actual transfers.
    pub app_data: AppData,

    /// The vault note being spent.
    pub resource: Resource,
    /// Nullifier secret derived from `label_preimage` per spec §4.3. Verified in-circuit.
    pub nf_key: NullifierKey,

    /// Multisig policy parameters; the SHA256 of this preimage MUST equal `resource.label_ref`.
    pub label_preimage: LabelPreimage,
    /// Sorted compressed pubkeys whose SHA256 concat MUST equal `label_preimage.pubkey_root`.
    /// Each pubkey is 33 bytes (SEC1 compressed secp256k1 point).
    #[serde_as(as = "Vec<[_; 33]>")]
    pub pubkeys: Vec<[u8; 33]>,
    /// K-of-N authorization. `signatures.len() == label_preimage.k`.
    pub signatures: Vec<SignerSlot>,

    /// The change resource preimage (a created vault note paired with the consumed via
    /// compliance). Quantity is part of the conservation equation:
    /// `external_sum_to_MSF + sum(recipient.quantity) + change.quantity == consumed.quantity`.
    pub change_resource: Resource,
    /// RM-internal recipients: created resources whose value is being transferred to other
    /// holders (other vaults, AnomaPay users, any RM-native recipient) without crossing
    /// the EVM boundary. Each recipient's commitment is verified to be in `action_tags`,
    /// and their quantities + change + external_sum must equal the consumed quantity.
    /// This is the AnomaPay-style private transfer path: PA only sees commitment updates,
    /// no `IERC20.Transfer` event, no `ExternalPayload` event for these.
    /// Empty Vec = pure EVM-withdraw mode (v0.4 behavior).
    pub recipient_resources: Vec<Resource>,
    /// The full action tag list, used to (a) reconstruct `actionTreeRoot` and (b) verify
    /// `change_resource.commitment()` and each `recipient_resources[i].commitment()` are in
    /// the action.
    pub action_tags: Vec<Digest>,
}

/// Witness for `multisig_v1` created branch (a fresh vault note being minted).
#[derive(Clone, Serialize, Deserialize)]
pub struct MultisigCreatedWitness {
    pub action_tree_root: Digest,
    pub app_data: AppData,

    pub resource: Resource,
    pub label_preimage: LabelPreimage,
}

/// Witness for `wrap_v1` inflow branch (a deposit's consumed ephemeral). Authorizes the
/// `WrapForwarder.transferFrom(depositor, MULTISIG_FORWARDER, amount)` call.
#[derive(Clone, Serialize, Deserialize)]
pub struct WrapInflowWitness {
    pub action_tree_root: Digest,
    pub app_data: AppData,

    pub resource: Resource,
    pub nf_key: NullifierKey,

    /// Label preimage of the paired created vault note. Used to bind:
    ///   - external_payload.token == label_preimage.token_addr
    pub paired_vault_label_preimage: LabelPreimage,
    /// Quantity of the paired created vault note. Used to bind:
    ///   - external_payload.amount == paired_vault_quantity
    pub paired_vault_quantity: u128,
    /// EVM address of the depositor (used in the WrapForwarder transferFrom call).
    pub depositor: [u8; 20],
}

/// Witness for `wrap_v1` outflow branch. The outflow ephemeral exists purely for compliance
/// per-kind balance — it doesn't carry an external payload (those live on the consumed
/// vault note, bound by the multisig signature).
#[derive(Clone, Serialize, Deserialize)]
pub struct WrapOutflowWitness {
    pub action_tree_root: Digest,
    pub app_data: AppData,

    pub resource: Resource,
    /// LabelPreimage matching `resource.label_ref` — establishes which vault-kind this
    /// outflow is balancing.
    pub label_preimage: LabelPreimage,
}

/// Tagged dispatch enum for the `multisig_v1` guest. The guest reads one of these via
/// `env::read()` and dispatches to the matching constraint function.
#[derive(Clone, Serialize, Deserialize)]
pub enum MultisigBranchWitness {
    Consumed(MultisigConsumedWitness),
    Created(MultisigCreatedWitness),
}

/// Tagged dispatch enum for the `wrap_v1` guest.
#[derive(Clone, Serialize, Deserialize)]
pub enum WrapBranchWitness {
    Inflow(WrapInflowWitness),
    Outflow(WrapOutflowWitness),
}
