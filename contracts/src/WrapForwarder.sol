// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";

import {IForwarder} from "./interfaces/IForwarder.sol";

/// @title WrapForwarder
/// @notice Singleton wrap forwarder. Routes deposits from any depositor into the canonical `MultisigForwarder`. The
/// destination is baked in at deploy — `wrap_v1` (the carrier circuit) constrains the deposit token + amount to match
/// the created vault note's quantity and labelRef.
contract WrapForwarder is IForwarder {
    using SafeERC20 for IERC20;

    enum Op {
        WRAP
    }

    address public immutable PA;
    address public immutable MULTISIG_FORWARDER;
    bytes32 public immutable WRAP_LOGIC_REF;

    error OnlyPA();
    error WrongLogic(bytes32 expected, bytes32 actual);
    error UnsupportedOp(Op op);

    constructor(address pa, address multisigForwarder, bytes32 wrapLogicRef) {
        PA = pa;
        MULTISIG_FORWARDER = multisigForwarder;
        WRAP_LOGIC_REF = wrapLogicRef;
    }

    /// @inheritdoc IForwarder
    function forwardCall(bytes32 logicRef, bytes calldata input) external returns (bytes memory) {
        if (msg.sender != PA) revert OnlyPA();
        if (logicRef != WRAP_LOGIC_REF) revert WrongLogic(WRAP_LOGIC_REF, logicRef);

        (Op op, address token, address from, uint256 amount, bytes memory expected) =
            abi.decode(input, (Op, address, address, uint256, bytes));

        if (op != Op.WRAP) revert UnsupportedOp(op);

        IERC20(token).safeTransferFrom(from, MULTISIG_FORWARDER, amount);
        return expected;
    }
}
