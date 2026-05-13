// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";

import {IForwarder} from "./interfaces/IForwarder.sol";

/// @title MultisigForwarder
/// @notice Singleton forwarder. Holds the ERC20s for every vault using this circuit version. Only the protocol adapter
/// can move tokens, and only when the carrier resource's logic is `wrap_v1` — that circuit binds the transfer's
/// (token, recipient, amount) to the outflow ephemeral's quantity and to the K-of-N signature on the consumed vault.
/// Per-vault accounting is virtual, enforced off-chain by the resource machine compliance circuit's per-kind balance.
contract MultisigForwarder is IForwarder {
    using SafeERC20 for IERC20;

    address public immutable PA;
    bytes32 public immutable WRAP_LOGIC_REF;

    error OnlyPA();
    error WrongLogic(bytes32 expected, bytes32 actual);

    constructor(address pa, bytes32 wrapLogicRef) {
        PA = pa;
        WRAP_LOGIC_REF = wrapLogicRef;
    }

    /// @inheritdoc IForwarder
    function forwardCall(bytes32 logicRef, bytes calldata input) external returns (bytes memory) {
        if (msg.sender != PA) revert OnlyPA();
        if (logicRef != WRAP_LOGIC_REF) revert WrongLogic(WRAP_LOGIC_REF, logicRef);

        (address token, address to, uint256 amount, bytes memory expected) =
            abi.decode(input, (address, address, uint256, bytes));

        IERC20(token).safeTransfer(to, amount);
        return expected;
    }
}
