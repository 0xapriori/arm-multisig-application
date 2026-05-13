//! Shared fixtures for host-side prove/verify tests.
//!
//! Builds a fully-formed `MultisigConsumedWitness` for a 2-of-3 vault that authorizes a single
//! transfer of N tokens. All cryptographic material (keys, signatures, resource preimages,
//! commitments) is derived deterministically from a seed for reproducibility.

use k256::ecdsa::signature::DigestSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};

use multisig_core::journal::{AppData, DeletionCriterion, ExpirableBlob};
use multisig_core::label::{LabelPreimage, NULLIFIER_KEY_DOMAIN};
use multisig_core::spend::{spend_message, RecipientCommitments};
use multisig_core::witness::{MultisigConsumedWitness, SignerSlot};

use anoma_rm_risc0::{
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use risc0_zkvm::sha::Digest;

pub const TEST_TOKEN: [u8; 20] = [0x11; 20];
pub const TEST_RECIPIENT: [u8; 20] = [0x22; 20];
pub const TEST_MULTISIG_FORWARDER: [u8; 20] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
];

pub struct TestVault {
    pub label: LabelPreimage,
    pub signers: Vec<SigningKey>,
    pub pubkeys: Vec<[u8; 33]>,
    pub nf_key: NullifierKey,
    pub nk_commitment: NullifierKeyCommitment,
}

impl TestVault {
    /// 2-of-3 vault, deterministic from `seed`.
    pub fn deterministic(seed: u8) -> Self {
        let signers: Vec<SigningKey> = (0..3)
            .map(|i| {
                let mut sk_bytes = [0u8; 32];
                sk_bytes[31] = seed;
                sk_bytes[30] = i;
                SigningKey::from_bytes(&sk_bytes.into()).expect("non-zero scalar")
            })
            .collect();

        let mut pks_unsorted: Vec<[u8; 33]> = signers
            .iter()
            .map(|sk| {
                let pt = sk.verifying_key().to_encoded_point(true);
                let mut pk = [0u8; 33];
                pk.copy_from_slice(pt.as_bytes());
                pk
            })
            .collect();

        // Sort pubkeys ascending (label requires sorted compressed pubkeys).
        let mut idx: Vec<usize> = (0..pks_unsorted.len()).collect();
        idx.sort_by(|&a, &b| pks_unsorted[a].cmp(&pks_unsorted[b]));
        let pubkeys: Vec<[u8; 33]> = idx.iter().map(|&i| pks_unsorted[i]).collect();
        let signers: Vec<SigningKey> = idx.iter().map(|&i| signers[i].clone()).collect();
        pks_unsorted.clear();

        let salt = {
            let mut s = [0u8; 32];
            s[0] = seed.wrapping_add(1);
            s
        };
        let label = LabelPreimage::new(TEST_TOKEN, 2, &pubkeys, salt).expect("valid label");

        let mut h = Sha256::new();
        h.update(NULLIFIER_KEY_DOMAIN);
        h.update(label.encode());
        let nf_key_bytes: [u8; 32] = h.finalize().into();
        let nf_key = NullifierKey::from_bytes(nf_key_bytes);
        let nk_commitment = nf_key.commit();

        Self {
            label,
            signers,
            pubkeys,
            nf_key,
            nk_commitment,
        }
    }

    pub fn label_ref_digest(&self) -> Digest {
        let bytes = self.label.label_ref();
        Digest::from_bytes(bytes)
    }

    pub fn build_resource(&self, quantity: u128, nonce: [u8; 32], rand_seed: [u8; 32]) -> Resource {
        Resource {
            logic_ref: Digest::default(), // placeholder; circuit doesn't enforce a specific value
            label_ref: self.label_ref_digest(),
            quantity,
            value_ref: Digest::default(),
            is_ephemeral: false,
            nonce,
            nk_commitment: self.nk_commitment,
            rand_seed,
        }
    }
}

/// Build the abi.encode(address forwarder, bytes input, bytes expected) blob for a single
/// MultisigForwarder transfer.
pub fn encode_external_transfer(
    forwarder: [u8; 20],
    token: [u8; 20],
    recipient: [u8; 20],
    amount: u128,
) -> Vec<u8> {
    let pad = |b: &[u8]| {
        let mut v = b.to_vec();
        let rem = v.len() % 32;
        if rem != 0 {
            v.extend(core::iter::repeat(0u8).take(32 - rem));
        }
        v
    };
    let u256_be = |v: u128| {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&v.to_be_bytes());
        out
    };

    // `expected` = abi.encode(true) = 32-byte word with last byte = 1
    let mut expected = [0u8; 32];
    expected[31] = 1;
    let expected = expected.to_vec();

    // Inner input = abi.encode(address token, address to, uint256 amount, bytes expected)
    let mut input = Vec::new();
    input.extend_from_slice(&[0u8; 12]);
    input.extend_from_slice(&token);
    input.extend_from_slice(&[0u8; 12]);
    input.extend_from_slice(&recipient);
    input.extend_from_slice(&u256_be(amount));
    input.extend_from_slice(&u256_be(128)); // expected offset
    input.extend_from_slice(&u256_be(expected.len() as u128));
    input.extend_from_slice(&pad(&expected));

    // Outer = abi.encode(address forwarder, bytes input, bytes expected)
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0u8; 12]);
    blob.extend_from_slice(&forwarder);
    blob.extend_from_slice(&u256_be(0x60)); // offset to input
    let padded_input = pad(&input);
    let expected_offset = 0x60u128 + 32 + padded_input.len() as u128;
    blob.extend_from_slice(&u256_be(expected_offset));
    blob.extend_from_slice(&u256_be(input.len() as u128));
    blob.extend_from_slice(&padded_input);
    blob.extend_from_slice(&u256_be(expected.len() as u128));
    blob.extend_from_slice(&pad(&expected));
    blob
}

/// Compute the spend_message that K-of-N must sign for a given consumed-vault witness.
/// Mirrors `constrain_multisig_consumed`'s spend_message construction.
pub fn compute_spend_message(witness: &MultisigConsumedWitness) -> [u8; 32] {
    use multisig_core::journal::{self, LogicInstance};
    let tag = witness
        .resource
        .tag(true, &witness.nf_key)
        .expect("resource tag");
    let instance = LogicInstance {
        tag: digest_to_array(&tag),
        is_consumed: true,
        action_tree_root: digest_to_array(&witness.action_tree_root),
        app_data: witness.app_data.clone(),
    };
    let bytes = journal::encode(&instance);
    let mut h = Sha256::new();
    h.update(&bytes);
    let journal_digest: [u8; 32] = h.finalize().into();
    let recipients = RecipientCommitments::new(
        witness
            .recipient_resources
            .iter()
            .map(|r| digest_to_array(&r.commitment()))
            .collect(),
    );
    spend_message(&journal_digest, &recipients)
}

fn digest_to_array(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// Sign `msg` with a SigningKey, producing a low-s DER-encoded signature.
pub fn sign_low_s_der(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(msg);
    let sig: Signature = sk.sign_digest(h);
    let normalized = sig.normalize_s().unwrap_or(sig);
    normalized.to_der().to_bytes().to_vec()
}

/// Build a complete MultisigConsumedWitness for a 2-of-3 vault that spends `quantity`
/// tokens (full amount, no change).
pub fn build_full_spend_witness(seed: u8, quantity: u128) -> MultisigConsumedWitness {
    let vault = TestVault::deterministic(seed);

    // Create the consumed vault note
    let mut nonce = [0u8; 32];
    nonce[0] = 0xCA;
    let mut rand_seed = [0u8; 32];
    rand_seed[0] = 0xFE;
    let resource = vault.build_resource(quantity, nonce, rand_seed);

    // Change note has quantity 0 (full spend); same labelRef (sticky).
    let mut change_nonce = [0u8; 32];
    change_nonce[0] = 0xCC;
    let change_resource = vault.build_resource(0, change_nonce, rand_seed);

    // External payload: single transfer of `quantity` to RECIPIENT via MULTISIG_FORWARDER
    let blob = encode_external_transfer(TEST_MULTISIG_FORWARDER, TEST_TOKEN, TEST_RECIPIENT, quantity);
    let app_data = AppData {
        resource_payload: vec![],
        discovery_payload: vec![],
        external_payload: vec![ExpirableBlob {
            deletion_criterion: DeletionCriterion::Never,
            blob,
        }],
        application_payload: vec![],
    };

    // Action tags = [consumed nullifier, change commitment] (order doesn't matter for our membership check)
    let tag = resource.tag(true, &vault.nf_key).expect("tag");
    let action_tags: Vec<Digest> = vec![tag, change_resource.commitment()];

    // Compute action_tree_root from a SHA256 hash chain of the tags (placeholder — the real
    // action tree is a SHA256 Merkle tree; for v0 we just commit a hash that the witness uses
    // consistently. PA's actionTreeRoot binding is independent of the in-circuit reconstruction
    // for this test.)
    let mut h = Sha256::new();
    for t in &action_tags {
        h.update(t.as_bytes());
    }
    let atr_bytes: [u8; 32] = h.finalize().into();
    let action_tree_root = Digest::from_bytes(atr_bytes);

    // Build a partial witness, then sign and fill in signatures.
    let mut witness = MultisigConsumedWitness {
        action_tree_root,
        app_data,
        resource,
        nf_key: vault.nf_key.clone(),
        label_preimage: vault.label.clone(),
        pubkeys: vault.pubkeys.clone(),
        signatures: vec![],
        change_resource,
        recipient_resources: vec![], // pure EVM-withdraw mode
        action_tags,
    };

    sign_witness(&mut witness, &vault.signers, &[0, 2]);
    witness
}

/// Build a MultisigConsumedWitness for a pure RM-internal transfer:
///   - consume vault A's note (Q tokens)
///   - create change note (Q-X) staying in vault A
///   - create recipient resource (X tokens) controlled by a different label_preimage
///   - NO external_payload — nothing crosses the EVM boundary
///   - PA only sees commitment updates; recipient address + amount are NOT public
///
/// `recipient_seed` controls the recipient vault's identity (different from `seed` so the
/// recipient is a distinct vault).
pub fn build_rm_internal_witness(
    seed: u8,
    recipient_seed: u8,
    consumed_quantity: u128,
    transfer_quantity: u128,
) -> MultisigConsumedWitness {
    assert!(transfer_quantity <= consumed_quantity);
    let vault = TestVault::deterministic(seed);
    let recipient_vault = TestVault::deterministic(recipient_seed);

    let mut nonce = [0u8; 32];
    nonce[0] = 0xCA;
    let mut rand_seed = [0u8; 32];
    rand_seed[0] = 0xFE;
    let resource = vault.build_resource(consumed_quantity, nonce, rand_seed);

    // Change stays in vault A
    let mut change_nonce = [0u8; 32];
    change_nonce[0] = 0xCC;
    let change_resource = vault.build_resource(consumed_quantity - transfer_quantity, change_nonce, rand_seed);

    // Recipient resource — different labelRef = different vault-kind. Built with the
    // recipient_vault's label so the recipient (a separate K-of-N policy) can spend it later.
    let mut recipient_nonce = [0u8; 32];
    recipient_nonce[0] = 0xDD;
    let recipient_resource = recipient_vault.build_resource(transfer_quantity, recipient_nonce, rand_seed);

    // No external_payload: pure RM-internal transfer
    let app_data = AppData::default();

    let tag = resource.tag(true, &vault.nf_key).expect("tag");
    let action_tags: Vec<Digest> = vec![tag, change_resource.commitment(), recipient_resource.commitment()];

    let mut h = Sha256::new();
    for t in &action_tags {
        h.update(t.as_bytes());
    }
    let atr_bytes: [u8; 32] = h.finalize().into();
    let action_tree_root = Digest::from_bytes(atr_bytes);

    let mut witness = MultisigConsumedWitness {
        action_tree_root,
        app_data,
        resource,
        nf_key: vault.nf_key.clone(),
        label_preimage: vault.label.clone(),
        pubkeys: vault.pubkeys.clone(),
        signatures: vec![],
        change_resource,
        recipient_resources: vec![recipient_resource],
        action_tags,
    };

    sign_witness(&mut witness, &vault.signers, &[0, 2]);
    witness
}

/// Build a hybrid: some value goes to a recipient (RM-internal, private), some goes out via
/// MultisigForwarder (EVM withdraw, public).
pub fn build_hybrid_witness(
    seed: u8,
    recipient_seed: u8,
    consumed: u128,
    rm_transfer: u128,
    evm_withdraw: u128,
) -> MultisigConsumedWitness {
    assert!(rm_transfer + evm_withdraw <= consumed);
    let vault = TestVault::deterministic(seed);
    let recipient_vault = TestVault::deterministic(recipient_seed);

    let change = consumed - rm_transfer - evm_withdraw;

    let mut nonce = [0u8; 32];
    nonce[0] = 0xCA;
    let mut rand_seed = [0u8; 32];
    rand_seed[0] = 0xFE;
    let resource = vault.build_resource(consumed, nonce, rand_seed);

    let mut change_nonce = [0u8; 32];
    change_nonce[0] = 0xCC;
    let change_resource = vault.build_resource(change, change_nonce, rand_seed);

    let mut recipient_nonce = [0u8; 32];
    recipient_nonce[0] = 0xDD;
    let recipient_resource = recipient_vault.build_resource(rm_transfer, recipient_nonce, rand_seed);

    let blob = encode_external_transfer(TEST_MULTISIG_FORWARDER, TEST_TOKEN, TEST_RECIPIENT, evm_withdraw);
    let app_data = AppData {
        resource_payload: vec![],
        discovery_payload: vec![],
        external_payload: vec![ExpirableBlob {
            deletion_criterion: DeletionCriterion::Never,
            blob,
        }],
        application_payload: vec![],
    };

    let tag = resource.tag(true, &vault.nf_key).expect("tag");
    let action_tags: Vec<Digest> = vec![tag, change_resource.commitment(), recipient_resource.commitment()];

    let mut h = Sha256::new();
    for t in &action_tags {
        h.update(t.as_bytes());
    }
    let atr_bytes: [u8; 32] = h.finalize().into();
    let action_tree_root = Digest::from_bytes(atr_bytes);

    let mut witness = MultisigConsumedWitness {
        action_tree_root,
        app_data,
        resource,
        nf_key: vault.nf_key.clone(),
        label_preimage: vault.label.clone(),
        pubkeys: vault.pubkeys.clone(),
        signatures: vec![],
        change_resource,
        recipient_resources: vec![recipient_resource],
        action_tags,
    };

    sign_witness(&mut witness, &vault.signers, &[0, 2]);
    witness
}

fn sign_witness(witness: &mut MultisigConsumedWitness, signers: &[SigningKey], indices: &[usize]) {
    let msg = compute_spend_message(witness);
    let mut signatures = Vec::new();
    for &i in indices {
        let sig = sign_low_s_der(&signers[i], &msg);
        signatures.push(SignerSlot {
            idx: i as u32,
            sig_der: sig,
        });
    }
    witness.signatures = signatures;
}
