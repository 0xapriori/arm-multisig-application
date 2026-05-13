// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title LogicJournal
/// @notice Independent reference implementation of `RiscZeroUtils.toJournal(Logic.Instance)` from anoma/pa-evm
/// v1.1.0. Used as a conformance oracle for the Rust core's journal encoder. NOT consumed by the forwarders at runtime.
/// @dev The PA's actual `RiscZeroUtils.toJournal` lives in a transitive RISC Zero dep; reproducing it here keeps the
/// conformance test free of that dep, and forces us to keep this library byte-equivalent to the canonical encoder.
library LogicJournal {
    enum DeletionCriterion {
        Immediately,
        Never
    }

    struct ExpirableBlob {
        DeletionCriterion deletionCriterion;
        bytes blob;
    }

    struct AppData {
        ExpirableBlob[] resourcePayload;
        ExpirableBlob[] discoveryPayload;
        ExpirableBlob[] externalPayload;
        ExpirableBlob[] applicationPayload;
    }

    struct Instance {
        bytes32 tag;
        bool isConsumed;
        bytes32 actionTreeRoot;
        AppData appData;
    }

    /// @notice Reverses the byte order of a uint32 — RISC Zero serializes journal field lengths and the bool flag as
    /// little-endian uint32. This matches `risc0-risc0-ethereum/contracts/src/Util.sol#reverseByteOrderUint32`.
    function reverseByteOrderUint32(uint32 input) internal pure returns (uint32 v) {
        v = input;
        v = ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8);
        v = (v >> 16) | (v << 16);
    }

    function encode(Instance memory instance) internal pure returns (bytes memory) {
        AppData memory appData = instance.appData;

        uint32 risc0BoolTrueLittleEndian = 0x01000000;
        uint32 risc0BoolFalseLittleEndian = 0x00000000;

        return abi.encodePacked(
            instance.tag,
            instance.isConsumed ? risc0BoolTrueLittleEndian : risc0BoolFalseLittleEndian,
            instance.actionTreeRoot,
            reverseByteOrderUint32(uint32(appData.resourcePayload.length)),
            encodePayload(appData.resourcePayload),
            reverseByteOrderUint32(uint32(appData.discoveryPayload.length)),
            encodePayload(appData.discoveryPayload),
            reverseByteOrderUint32(uint32(appData.externalPayload.length)),
            encodePayload(appData.externalPayload),
            reverseByteOrderUint32(uint32(appData.applicationPayload.length)),
            encodePayload(appData.applicationPayload)
        );
    }

    function encodePayload(ExpirableBlob[] memory payload) internal pure returns (bytes memory out) {
        uint256 n = payload.length;
        for (uint256 i = 0; i < n; ++i) {
            out = abi.encodePacked(
                out,
                uint8(payload[i].deletionCriterion),
                reverseByteOrderUint32(uint32(payload[i].blob.length)),
                payload[i].blob
            );
        }
    }

    function digest(Instance memory instance) internal pure returns (bytes32) {
        return sha256(encode(instance));
    }
}
