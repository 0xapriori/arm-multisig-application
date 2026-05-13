// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {LogicJournal} from "../src/libs/LogicJournal.sol";

/// @notice Snapshot test for the LogicJournal encoding. The hex dumps emitted here are the conformance oracle for the
/// Rust `multisig-core::journal` encoder. If you change LogicJournal.sol, regenerate the Rust test fixtures by
/// running `forge test --match-test test_JournalReference -vv` and pasting the hex into
/// coordinator/crates/multisig-core/tests/journal_conformance.rs.
contract LogicJournalTest is Test {
    /// Empty appData, isConsumed=false, fixed tag/root.
    function test_JournalReference_empty() public {
        LogicJournal.Instance memory ins = LogicJournal.Instance({
            tag: bytes32(uint256(0xAAAA)),
            isConsumed: false,
            actionTreeRoot: bytes32(uint256(0xBBBB)),
            appData: LogicJournal.AppData({
                resourcePayload: new LogicJournal.ExpirableBlob[](0),
                discoveryPayload: new LogicJournal.ExpirableBlob[](0),
                externalPayload: new LogicJournal.ExpirableBlob[](0),
                applicationPayload: new LogicJournal.ExpirableBlob[](0)
            })
        });

        bytes memory journal = LogicJournal.encode(ins);
        bytes32 dgst = LogicJournal.digest(ins);

        // Expected layout (76 bytes):
        //   tag (32)  ‖  isConsumed (4)  ‖  actionTreeRoot (32)  ‖  4×uint32_le(0)
        // = 0x...aaaa(32) ‖ 0x00000000(4) ‖ 0x...bbbb(32) ‖ 16 zero bytes for the four payload-array length prefixes
        assertEq(journal.length, 32 + 4 + 32 + 4 * 4, "journal length");

        emit log_named_bytes("journal_empty.bytes", journal);
        emit log_named_bytes32("journal_empty.digest", dgst);
    }

    /// One external payload blob (the most relevant case for spend actions).
    function test_JournalReference_oneExternal() public {
        LogicJournal.ExpirableBlob[] memory ext = new LogicJournal.ExpirableBlob[](1);
        ext[0] = LogicJournal.ExpirableBlob({
            deletionCriterion: LogicJournal.DeletionCriterion.Never,
            blob: hex"deadbeef"
        });

        LogicJournal.Instance memory ins = LogicJournal.Instance({
            tag: bytes32(uint256(0x1111)),
            isConsumed: true,
            actionTreeRoot: bytes32(uint256(0x2222)),
            appData: LogicJournal.AppData({
                resourcePayload: new LogicJournal.ExpirableBlob[](0),
                discoveryPayload: new LogicJournal.ExpirableBlob[](0),
                externalPayload: ext,
                applicationPayload: new LogicJournal.ExpirableBlob[](0)
            })
        });

        bytes memory journal = LogicJournal.encode(ins);
        bytes32 dgst = LogicJournal.digest(ins);

        emit log_named_bytes("journal_oneExternal.bytes", journal);
        emit log_named_bytes32("journal_oneExternal.digest", dgst);
    }

    function test_reverseByteOrderUint32() public {
        assertEq(LogicJournal.reverseByteOrderUint32(0x01000000), uint32(1));
        assertEq(LogicJournal.reverseByteOrderUint32(uint32(1)), 0x01000000);
        assertEq(LogicJournal.reverseByteOrderUint32(0xDEADBEEF), 0xEFBEADDE);
    }
}
