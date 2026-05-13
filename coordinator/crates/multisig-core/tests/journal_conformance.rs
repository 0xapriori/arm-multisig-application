//! Cross-language conformance: the Rust `journal::encode` must produce byte-identical output to
//! the Solidity `LogicJournal.encode`. The fixtures below were emitted by
//! `forge test --match-test test_JournalReference -vvv` against `contracts/test/LogicJournal.t.sol`.
//!
//! If you change the encoding on either side, regenerate both: run forge, copy the hex from the
//! `journal_*.bytes` and `journal_*.digest` log lines, and update the constants below.

use multisig_core::journal::{encode, digest, AppData, DeletionCriterion, ExpirableBlob, LogicInstance};

const EMPTY_BYTES_HEX: &str = "000000000000000000000000000000000000000000000000000000000000aaaa00000000000000000000000000000000000000000000000000000000000000000000bbbb00000000000000000000000000000000";
const EMPTY_DIGEST_HEX: &str = "083e5a6901292fed391b1982d083f249447f11ff243bcff33b30cc282c8fe0ea";

const ONE_EXTERNAL_BYTES_HEX: &str = "00000000000000000000000000000000000000000000000000000000000011110100000000000000000000000000000000000000000000000000000000000000000022220000000000000000010000000104000000deadbeef00000000";
const ONE_EXTERNAL_DIGEST_HEX: &str = "94f50e70ae40e56bdf2b339572935eca4848a6ef22174aff9ddc2b3708608a25";

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn bytes32_le_word(value: u16) -> [u8; 32] {
    // Solidity's `bytes32(uint256(0xAAAA))` produces a 32-byte big-endian word: 30 zero bytes
    // then the two value bytes.
    let mut out = [0u8; 32];
    out[30..].copy_from_slice(&value.to_be_bytes());
    out
}

#[test]
fn journal_matches_solidity_empty() {
    let ins = LogicInstance {
        tag: bytes32_le_word(0xAAAA),
        is_consumed: false,
        action_tree_root: bytes32_le_word(0xBBBB),
        app_data: AppData::default(),
    };

    let actual = encode(&ins);
    assert_eq!(
        hex::encode(&actual),
        EMPTY_BYTES_HEX,
        "journal bytes diverge from Solidity LogicJournal.encode"
    );
    assert_eq!(
        hex::encode(digest(&ins)),
        EMPTY_DIGEST_HEX,
        "journal digest diverges from Solidity LogicJournal.digest"
    );

    // Length sanity: 32 (tag) + 4 (bool_le) + 32 (actionTreeRoot) + 4*4 (four empty length prefixes) = 84
    assert_eq!(actual.len(), 84);
    assert_eq!(actual.len(), hex_to_vec(EMPTY_BYTES_HEX).len());
}

#[test]
fn journal_matches_solidity_one_external() {
    let ins = LogicInstance {
        tag: bytes32_le_word(0x1111),
        is_consumed: true,
        action_tree_root: bytes32_le_word(0x2222),
        app_data: AppData {
            resource_payload: vec![],
            discovery_payload: vec![],
            external_payload: vec![ExpirableBlob {
                deletion_criterion: DeletionCriterion::Never,
                blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            application_payload: vec![],
        },
    };

    assert_eq!(hex::encode(encode(&ins)), ONE_EXTERNAL_BYTES_HEX);
    assert_eq!(hex::encode(digest(&ins)), ONE_EXTERNAL_DIGEST_HEX);
}
