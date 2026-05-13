//! ECDSA-secp256k1 signature verification with low-s enforcement.
//!
//! Per spec §5.3 step 12: signers sign over `spend_message` using ECDSA-secp256k1, with low-s
//! required (so two malleable forms of the same signature can't pass distinct-signer checks).
//! The signature curve hash is SHA256 (NOT keccak); we sign over the raw `spend_message` bytes.

use k256::ecdsa::signature::DigestVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for the signed message constructor (see `spend::spend_message`).
pub const K_DOMAIN_SEP: &[u8] = b"anoma.multisig.v1.spend";

#[derive(Debug, Error)]
pub enum SigError {
    #[error("invalid compressed pubkey")]
    InvalidPubkey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("signature must be low-s")]
    NonNormalizedS,
    #[error("signature did not verify")]
    VerifyFailed,
}

/// Verify a single ECDSA-secp256k1 signature with low-s enforcement.
///
/// `pubkey_compressed` must be a 33-byte SEC1 compressed point.
/// `sig_der` is a DER-encoded signature.
/// `msg` is the raw message to be SHA256-hashed and verified against.
pub fn verify_secp256k1(
    pubkey_compressed: &[u8; 33],
    msg: &[u8],
    sig_der: &[u8],
) -> Result<(), SigError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_compressed).map_err(|_| SigError::InvalidPubkey)?;

    let sig = Signature::from_der(sig_der).map_err(|_| SigError::InvalidSignature)?;

    // Low-s enforcement: reject any signature that is NOT already in normalized (low-s) form.
    if sig.normalize_s().is_some() {
        return Err(SigError::NonNormalizedS);
    }

    let mut hasher = Sha256::new();
    hasher.update(msg);
    vk.verify_digest(hasher, &sig).map_err(|_| SigError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::DigestSigner;
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    fn sign_low_s(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let sig: Signature = sk.sign_digest(hasher);
        // Make sure we're producing a low-s signature
        let normalized = sig.normalize_s().unwrap_or(sig);
        normalized.to_der().to_bytes().to_vec()
    }

    #[test]
    fn verify_round_trip() {
        let sk = SigningKey::random(&mut OsRng);
        let pk_pt = sk.verifying_key().to_encoded_point(true);
        let pk: [u8; 33] = pk_pt.as_bytes().try_into().unwrap();

        let msg = b"hello world";
        let sig = sign_low_s(&sk, msg);

        assert!(verify_secp256k1(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn rejects_high_s() {
        // Construct a valid low-s signature, then flip s to (n - s) to produce its high-s twin.
        // The high-s signature is mathematically valid for the same message and pubkey, but
        // verify_secp256k1 must reject it via the low-s enforcement check.
        let sk = SigningKey::random(&mut OsRng);
        let pk_pt = sk.verifying_key().to_encoded_point(true);
        let pk: [u8; 33] = pk_pt.as_bytes().try_into().unwrap();

        let msg = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let sig: Signature = sk.sign_digest(hasher);

        // Make sure we start from low-s (k256 normalizes by default at sign time, but be explicit).
        let low_sig = sig.normalize_s().unwrap_or(sig);
        // Build the high-s twin by negating s on the secp256k1 scalar field.
        let (r_bytes, s_low_bytes) = {
            let sb = low_sig.to_bytes(); // 64 bytes: r ‖ s
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sb[..32]);
            s.copy_from_slice(&sb[32..]);
            (r, s)
        };
        let s_low = k256::Scalar::from(
            k256::elliptic_curve::scalar::ScalarPrimitive::<k256::Secp256k1>::from_slice(&s_low_bytes).unwrap(),
        );
        let s_high = -s_low;
        let s_high_bytes: [u8; 32] = k256::elliptic_curve::scalar::ScalarPrimitive::from(s_high).to_bytes().into();
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&r_bytes);
        concat[32..].copy_from_slice(&s_high_bytes);
        let high_sig = Signature::from_bytes(&concat.into()).unwrap();
        let high_der = high_sig.to_der().to_bytes().to_vec();

        assert!(matches!(
            verify_secp256k1(&pk, msg, &high_der),
            Err(SigError::NonNormalizedS)
        ));
    }

    #[test]
    fn rejects_wrong_message() {
        let sk = SigningKey::random(&mut OsRng);
        let pk_pt = sk.verifying_key().to_encoded_point(true);
        let pk: [u8; 33] = pk_pt.as_bytes().try_into().unwrap();

        let sig = sign_low_s(&sk, b"hello");
        assert!(matches!(
            verify_secp256k1(&pk, b"world", &sig),
            Err(SigError::VerifyFailed)
        ));
    }
}
