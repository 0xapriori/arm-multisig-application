// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";

import {MultisigForwarder} from "../src/MultisigForwarder.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract MultisigForwarderTest is Test {
    MultisigForwarder internal fwd;
    MockERC20 internal token;

    address internal constant PA = address(0xAAAA);
    bytes32 internal constant WRAP_LOGIC_REF = bytes32(uint256(0x57AAB));
    bytes32 internal constant WRONG_LOGIC_REF = bytes32(uint256(0xBAD));

    address internal constant RECIPIENT = address(0xCAFE);
    address internal constant ATTACKER = address(0xDEAD);

    function setUp() public {
        fwd = new MultisigForwarder(PA, WRAP_LOGIC_REF);
        token = new MockERC20();
        token.mint(address(fwd), 1_000_000e18);
    }

    function _input(address to, uint256 amount, bytes memory expected) internal view returns (bytes memory) {
        return abi.encode(address(token), to, amount, expected);
    }

    function test_immutables() public {
        assertEq(fwd.PA(), PA);
        assertEq(fwd.WRAP_LOGIC_REF(), WRAP_LOGIC_REF);
    }

    function test_forwardCall_succeeds_when_called_by_PA_with_correct_logicRef() public {
        bytes memory expected = abi.encode(true);
        bytes memory input = _input(RECIPIENT, 100e18, expected);

        vm.prank(PA);
        bytes memory output = fwd.forwardCall(WRAP_LOGIC_REF, input);

        assertEq(keccak256(output), keccak256(expected), "output must equal expected");
        assertEq(token.balanceOf(RECIPIENT), 100e18);
        assertEq(token.balanceOf(address(fwd)), 1_000_000e18 - 100e18);
    }

    function test_forwardCall_reverts_when_caller_is_not_PA() public {
        bytes memory input = _input(RECIPIENT, 100e18, abi.encode(true));

        vm.prank(ATTACKER);
        vm.expectRevert(MultisigForwarder.OnlyPA.selector);
        fwd.forwardCall(WRAP_LOGIC_REF, input);
    }

    function test_forwardCall_reverts_when_logicRef_does_not_match() public {
        bytes memory input = _input(RECIPIENT, 100e18, abi.encode(true));

        vm.prank(PA);
        vm.expectRevert(abi.encodeWithSelector(MultisigForwarder.WrongLogic.selector, WRAP_LOGIC_REF, WRONG_LOGIC_REF));
        fwd.forwardCall(WRONG_LOGIC_REF, input);
    }

    function test_forwardCall_reverts_when_balance_insufficient() public {
        bytes memory input = _input(RECIPIENT, 10_000_000e18, abi.encode(true));

        vm.prank(PA);
        vm.expectRevert();
        fwd.forwardCall(WRAP_LOGIC_REF, input);
    }

    /// Direct external calls (bypassing the PA) must always revert. This is the property that makes the singleton
    /// safe — even if the canonical RISC0 verifier is paused, no caller other than the PA can move funds.
    function testFuzz_forwardCall_reverts_for_any_non_PA_caller(address caller, bytes32 logicRef, bytes calldata input)
        public
    {
        vm.assume(caller != PA);

        vm.prank(caller);
        vm.expectRevert(MultisigForwarder.OnlyPA.selector);
        fwd.forwardCall(logicRef, input);
    }

    /// Per spec §10: even when called by the PA, only proofs whose carrier resource has WRAP_LOGIC_REF can move funds.
    function testFuzz_forwardCall_reverts_for_wrong_logic_when_called_by_PA(bytes32 logicRef) public {
        vm.assume(logicRef != WRAP_LOGIC_REF);
        bytes memory input = _input(RECIPIENT, 1, abi.encode(true));

        vm.prank(PA);
        vm.expectRevert(abi.encodeWithSelector(MultisigForwarder.WrongLogic.selector, WRAP_LOGIC_REF, logicRef));
        fwd.forwardCall(logicRef, input);
    }
}
