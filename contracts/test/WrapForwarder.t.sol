// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";

import {WrapForwarder} from "../src/WrapForwarder.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract WrapForwarderTest is Test {
    WrapForwarder internal fwd;
    MockERC20 internal token;

    address internal constant PA = address(0xAAAA);
    address internal constant MULTISIG_FORWARDER = address(0x1175167);
    bytes32 internal constant WRAP_LOGIC_REF = bytes32(uint256(0x57AAB));
    bytes32 internal constant WRONG_LOGIC_REF = bytes32(uint256(0xBAD));

    address internal constant DEPOSITOR = address(0xCAFE);
    address internal constant ATTACKER = address(0xDEAD);

    function setUp() public {
        fwd = new WrapForwarder(PA, MULTISIG_FORWARDER, WRAP_LOGIC_REF);
        token = new MockERC20();
        token.mint(DEPOSITOR, 1_000_000e18);
        vm.prank(DEPOSITOR);
        token.approve(address(fwd), type(uint256).max);
    }

    function _input(WrapForwarder.Op op, address from, uint256 amount, bytes memory expected)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(op, address(token), from, amount, expected);
    }

    function test_immutables() public {
        assertEq(fwd.PA(), PA);
        assertEq(fwd.MULTISIG_FORWARDER(), MULTISIG_FORWARDER);
        assertEq(fwd.WRAP_LOGIC_REF(), WRAP_LOGIC_REF);
    }

    function test_forwardCall_routes_to_canonical_destination() public {
        bytes memory expected = abi.encode(true);
        bytes memory input = _input(WrapForwarder.Op.WRAP, DEPOSITOR, 100e18, expected);

        vm.prank(PA);
        bytes memory output = fwd.forwardCall(WRAP_LOGIC_REF, input);

        assertEq(keccak256(output), keccak256(expected));
        assertEq(token.balanceOf(MULTISIG_FORWARDER), 100e18);
        assertEq(token.balanceOf(DEPOSITOR), 1_000_000e18 - 100e18);
    }

    function test_forwardCall_reverts_when_caller_is_not_PA() public {
        bytes memory input = _input(WrapForwarder.Op.WRAP, DEPOSITOR, 100e18, abi.encode(true));

        vm.prank(ATTACKER);
        vm.expectRevert(WrapForwarder.OnlyPA.selector);
        fwd.forwardCall(WRAP_LOGIC_REF, input);
    }

    function test_forwardCall_reverts_when_logicRef_does_not_match() public {
        bytes memory input = _input(WrapForwarder.Op.WRAP, DEPOSITOR, 100e18, abi.encode(true));

        vm.prank(PA);
        vm.expectRevert(abi.encodeWithSelector(WrapForwarder.WrongLogic.selector, WRAP_LOGIC_REF, WRONG_LOGIC_REF));
        fwd.forwardCall(WRONG_LOGIC_REF, input);
    }

    function test_forwardCall_reverts_without_depositor_approval() public {
        // Use a fresh depositor that has not approved
        address freshDepositor = address(0xBEEF);
        token.mint(freshDepositor, 100e18);

        bytes memory input = _input(WrapForwarder.Op.WRAP, freshDepositor, 100e18, abi.encode(true));

        vm.prank(PA);
        vm.expectRevert();
        fwd.forwardCall(WRAP_LOGIC_REF, input);
    }

    function testFuzz_forwardCall_reverts_for_any_non_PA_caller(address caller, bytes calldata input) public {
        vm.assume(caller != PA);

        vm.prank(caller);
        vm.expectRevert(WrapForwarder.OnlyPA.selector);
        fwd.forwardCall(WRAP_LOGIC_REF, input);
    }
}
