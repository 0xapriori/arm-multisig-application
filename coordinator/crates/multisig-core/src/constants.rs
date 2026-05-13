//! Compile-time constants pinned by the design — these are what guests bake in and what
//! signers must trust transitively. Changing any of them = new circuit version.

/// EVM address length (20 bytes).
pub const MULTISIG_FORWARDER_ADDRESS_LEN: usize = 20;
pub const WRAP_FORWARDER_ADDRESS_LEN: usize = 20;

/// `WrapForwarder.Op::WRAP` discriminant. Solidity `enum Op { WRAP }` ⇒ uint8(0).
pub const WRAP_FORWARDER_OP_WRAP: u8 = 0;
