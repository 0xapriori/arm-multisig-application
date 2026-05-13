# arm-multisig-application

A k-of-n multi-signature vault for ERC20s, built as an Anoma Resource Machine application on top of the canonical [`anoma/pa-evm`](https://github.com/anoma/pa-evm) protocol adapter (RISC Zero / ARM backend).

## Layout

```
Cargo.toml                                      top-level Rust workspace
contracts/                                      Solidity — Foundry project
  src/MultisigForwarder.sol                     singleton vault forwarder
  src/WrapForwarder.sol                         singleton deposit router
  src/interfaces/IForwarder.sol                 vendored from anoma/pa-evm
  src/libs/LogicJournal.sol                     conformance reference for journal encoding
  test/                                         16 tests, all passing
coordinator/crates/multisig-core/               pure-Rust constraint logic
  src/journal.rs                                  PA-format Logic.Instance journal encoder
  src/label.rs                                    label_preimage (n,k,pubkey_root,salt,token)
  src/sig.rs                                      ECDSA secp256k1 with low-s enforcement
  src/spend.rs                                    spend_message construction
  src/witness.rs                                  branch witness types
  src/constrain.rs                                full constraint logic for all 4 branches
  tests/journal_conformance.rs                    Rust journal == Solidity journal (byte-equal)
circuits/multisig-v1/                            real RISC Zero guest + host facade
  methods/guest/                                  guest binary (env::read witness, commit journal)
  methods/                                        risc0-build invocation, ELF + image ID
  src/lib.rs                                      prove_consumed / prove_created helpers
circuits/wrap-v1/                                same shape for the wrap circuit
host/                                            integration tests: prove + verify end-to-end
  tests/native_constraints.rs                     fast tests of the constraint logic
  tests/prove_and_verify.rs                       full RISC Zero proof generation + verification
SPEC.md                                          full design spec (mirrored below)
```

## Implementation status

| Component | Status | Notes |
|---|---|---|
| Spec (`SPEC.md`) | ✅ v0.5 | singleton forwarder + EVM-withdraw + RM-internal-transfer modes (AnomaPay-style private transfers) |
| `MultisigForwarder.sol` | ✅ | singleton, immutable, `msg.sender == PA` + `WRAP_LOGIC_REF` gated |
| `WrapForwarder.sol` | ✅ | singleton, destination baked in (canonical `MultisigForwarder`) |
| Foundry tests | ✅ 16/16 passing | gating, transfer paths, fuzz, journal conformance oracle |
| `multisig-core` (Rust) | ✅ | label preimage, journal encoding, ECDSA secp256k1 low-s, witness types, constraint logic, RM-internal recipient binding |
| `multisig-core` tests | ✅ 19/19 passing | unit + cross-language journal conformance vs Solidity reference |
| `multisig_v1` RISC Zero guest | ✅ compiled to ELF | reads `MultisigBranchWitness`, dispatches consumed/created, commits PA-format journal |
| `wrap_v1` RISC Zero guest | ✅ compiled to ELF | reads `WrapBranchWitness`, dispatches inflow/outflow |
| `host` native tests | ✅ 15/15 passing | EVM-withdraw + RM-internal + hybrid + 6 adversarial cases (recipient swap, conservation breaks, etc.) |
| `host` prove+verify (dev mode) | ✅ passing | end-to-end zkVM execution + receipt verification with `RISC0_DEV_MODE=1` |
| `host` prove+verify (real proof) | ⬜ untested in session | will work; just slow (multi-minute Groth16/Succinct proof generation) |
| Coordinator CLI | ⬜ TODO | library exists; CLI wrapper not built |
| `MULTISIG_FORWARDER` address pin in guest | 🟡 placeholder `0xAA…AA` | replace with deployed address before compiling production circuit; image ID changes too (= new logicRef = hard fork) |
| Live PA integration on Base | ⬜ TODO | needs (1) production circuit with real address pin, (2) PA deployment on Base, (3) prover ↔ Base bridge |

## Build & test

```
# Solidity (16 tests)
cd contracts && forge install && forge test -vv

# Rust constraint logic (19 unit + conformance)
cargo test -p multisig-core

# Native host integration tests (9 adversarial cases, no zkVM)
cargo test -p arm-multisig-host --test native_constraints

# Real proof generation + verification (dev mode = fast)
RISC0_DEV_MODE=1 cargo test -p arm-multisig-host --test prove_and_verify -- --nocapture

# Real proof generation + verification (no dev mode = slow, real cryptographic proof)
cargo test -p arm-multisig-host --test prove_and_verify -- --nocapture
```

First-time host build compiles the RISC Zero guest crates to RISC-V ELFs (~3 min on M-series Mac). Requires the `cargo-risczero` toolchain (`rzup install`).

## Trust model — read this first

The PA owner can permanently brick all vaults via `emergencyStop()`. `MultisigForwarder` requires `msg.sender == PA`, so a stopped PA = unrecoverable funds. v1 testnet runs against canonical PA; **mainnet vaults SHOULD fork the PA with a multi-sig owner.** Full table in §2 of the spec.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

`contracts/src/interfaces/IForwarder.sol` is vendored from [anoma/pa-evm](https://github.com/anoma/pa-evm) and retains its upstream MIT license.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.

---

# Design spec


**Version:** 0.5
**Target:** canonical [`anoma/pa-evm`](https://github.com/anoma/pa-evm) at PA `v1.1.0`, RISC Zero verifier selector `0x73c457ba`.
**Status:** design — partial implementation

## 1. Scope

A k-of-n multi-signature vault on the Anoma Resource Machine (EVM protocol adapter) supporting two spend modes:

- **EVM withdraw** — K-of-N authorizes a transfer to an external Ethereum address via a singleton `MultisigForwarder`. Recipient + amount are public (necessarily — the ERC-20 `Transfer` event is part of the standard).
- **RM-internal transfer** — K-of-N authorizes the value to be re-issued as a resource controlled by another RM holder (another vault, an AnomaPay user, any RM-native recipient). Recipient + amount stay private; PA only sees commitment updates. This mirrors AnomaPay's user-to-user `transfer` flow.

A single spend can mix both (hybrid mode). The `multisig_v1` circuit binds K-of-N authorization to both the EVM-side external payloads (via journal_digest) and the RM-internal recipient commitments (via the spend message).

Properties:
- Vault state is RM resources (a "kind" derived from `labelRef`), not a Solidity account.
- Signer set is committed in `labelRef` but not publicly revealed.
- Spend authorization is a RISC Zero logic proof verified via the existing `ProtocolAdapter`.
- A single `MultisigForwarder` instance holds the ERC-20s of *all* vaults using this circuit; per-vault accounting is virtual (RM-native), enforced by the compliance circuit's per-kind balance.
- Movement is atomic and proof-gated by the PA.

### Privacy properties

Privacy depends on which spend mode is used.

**Always private:**
- **Signer set.** Pubkeys are committed in `labelRef` and never revealed on-chain.
- **Policy parameters.** `k`, `n`, and `salt` are part of the `labelRef` preimage; observers see only the hash.
- **Vault discoverability.** Only parties holding `label_preimage` can derive the vault's nullifier key and locate its notes in the commitment tree.
- **Vault balance.** Notes are commitments; total holdings per vault aren't directly readable from chain state (though the singleton forwarder's aggregate ERC-20 balance is).

**Private under RM-internal transfers** (recipient is another RM holder, no EVM crossing):
- **Recipient.** PA only sees a commitment getting added to the tree. The recipient's identity is hidden — anyone holding the recipient's discovery key can find the resource; nobody else can.
- **Amount.** The recipient resource's quantity is part of the preimage, not the commitment.
- **Token.** Same — encoded in `labelRef` of the recipient resource; not visible.

This is the same privacy model AnomaPay's user-to-user `transfer` provides today.

**Public under EVM withdrawals** (recipient is an external Ethereum address):
- Recipient, amount, and token are visible via `ExternalPayload` and `IERC20.Transfer` events. This is a hard EVM-boundary constraint — the standard ERC-20 `Transfer(from, to, value)` event is mandatory and there's no way for a non-shielded ERC-20 to hide it. Confidential transfers to EVM addresses require a different protocol (Aztec-style mixer, shielded ERC-20); see §13.

### Non-goals (v1)

- Native ETH (WETH only).
- Composition with non-multisig logics in the same action (works mechanically; not specified here).
- Relayer / fee-payment mechanism.
- Dynamic signer-set Merkle trees (fixed N ≤ 32, full set inside `labelRef` preimage).
- Token allowlists (the same K-of-N controls every ERC20 the forwarder holds).

## 2. Trust assumptions

In order of weight:

| # | Trust | Mitigation |
|---|---|---|
| T1 | PA owner can permanently brick the system via `emergencyStop()`. Vault funds become unrecoverable (`MultisigForwarder` requires `msg.sender == PA`). | Fork `ProtocolAdapter` with a multi-sig owner or a null owner. Reuse canonical RISC0 verifier router. |
| T2 | RISC0 verifier router can be paused by *its* owner, also bricking the PA. | Inherent. Fork the router if T1 is forked. |
| T3 | Aggregation circuit verifying key is hardcoded (`0x213b…0827`). | Inherent to `pa-evm`. |
| T4 | Compliance circuit verifying key is hardcoded (`0x919e…314d`). | Inherent. |
| T5 | RISC0 soundness. | Inherent. |
| T5b | RISC Zero verifier selector pinned to `0x73c457ba` (`Versioning._RISC_ZERO_VERIFIER_SELECTOR`). PA's `_checkSelector` rejects proofs whose first 4 bytes don't match. Toolchain version drift = unspendable notes. | Pin the prover toolchain version that emits this selector; bake the selector into the off-chain coordinator's smoke test. |
| T6 | Off-chain signers actually verify what they sign before producing signatures. | Coordinator UX requirements (§9.2). |
| T7 | Out-of-band signaling: signers know the full `label_preimage` (forwarder address, salt, pubkey set). Loss of `label_preimage` = funds discoverable but not spendable. | Backup `label_preimage` alongside private keys. |

T1 is the dominant constraint. v1 testnet runs against canonical PA; mainnet vaults SHOULD fork.

## 3. Architecture

```
┌────────────────┐     submit Tx      ┌──────────────────┐
│   Coordinator  │ ─────────────────► │ ProtocolAdapter  │
│   (off-chain)  │                    │   (pa-evm)       │
└────────────────┘                    └────────┬─────────┘
        ▲                                      │ forwardCall(logicRef, input)
        │ collect K signatures                 │ msg.sender == PA
        │                                      ▼
┌────────────────┐                    ┌──────────────────┐
│  N signers     │                    │ MultisigForwarder│ <- singleton
│ (off-chain)    │                    │  (holds ERC20s   │    (per-vault accounting
└────────────────┘                    │   for all vaults)│     is virtual, enforced
                                      └──────────────────┘     by compliance + wrap_v1)
                                            ▲
                                            │ on deposit
                                      ┌─────┴──────┐
                                      │WrapForwarder│ <- singleton
                                      └─────────────┘
```

### Contracts

- `MultisigForwarder` — `IForwarder`. **Singleton.** Holds the ERC20s of every vault using this circuit version. Spends on PA instruction. No admin. Address is pinned as a constant in the `wrap_v1` and `multisig_v1` circuits.
- `WrapForwarder` — `IForwarder`. **Singleton.** Custodies incoming `transferFrom` and routes deposited tokens to the canonical `MultisigForwarder`.
- (optional) `ProtocolAdapterForked` — replace `emergencyStopCaller` if mitigating T1.

### Circuits (RISC0 guests)

- `multisig_v1` — k-of-n logic for vault notes.
- `wrap_v1` — wrap/unwrap balance bookkeeping for ephemeral inflow/outflow resources.

## 4. Resource layout

### 4.1 Vault note

| Field | Value |
|---|---|
| `logicRef` | RISC0 image ID of `multisig_v1` |
| `labelRef` | `SHA256(label_preimage)` — see §4.2 |
| `valueRef` | `SHA256(empty)` (reserved for per-note metadata) |
| `nullifierKeyCommitment` | `SHA256(nullifier_key)` — see §4.3 |
| `quantity` | ERC20 amount in raw token units, ≤ 2¹²⁸ − 1 |
| `nonce` | Set by compliance: equals consumed-resource's nullifier (RM invariant) |
| `randSeed` | Uniform 32-byte random, used by discovery encryption |
| `ephemeral` | `false` |

### 4.2 `label_preimage`

```
label_preimage =
    "anoma.multisig.v1"      // 17-byte domain
 || token_addr               // 20 bytes (ERC20)
 || n                        //  1 byte  (1 ≤ n ≤ 32)
 || k                        //  1 byte  (1 ≤ k ≤ n)
 || pubkey_root              // 32 bytes (SHA256 of canonical pubkey concat)
 || salt                     // 32 bytes (uniform random, non-zero)
```

Total: 103 bytes. Removed `forwarder_addr` (now a global circuit constant — `MULTISIG_FORWARDER` is singleton).

`pubkey_root = SHA256(pk_0 ‖ pk_1 ‖ … ‖ pk_{n-1})` where each `pk_i` is a 33-byte compressed secp256k1 point and the array is sorted in lexicographic order.

`salt` blocks brute-forcing the policy from observed `labelRef`s.

### 4.3 Nullifier key derivation

```
nullifier_key            = SHA256("anoma.multisig.v1.nfk-key" ‖ label_preimage)
nullifierKeyCommitment   = SHA256(nullifier_key)
```

Anyone holding `label_preimage` can derive the nullifier and submit a spend. Authorization lives entirely in the K-of-N signature check; the nullifier key is just a submission key.

### 4.4 Ephemeral inflow / outflow

`ephemeral = true`, `logicRef = wrap_v1` image ID, same `labelRef` as the paired vault note (so kind matches and the per-unit delta balances).

## 5. `multisig_v1` circuit

### 5.1 Public inputs (the `Logic.Instance`)

- `tag` — nullifier (consumed) or commitment (created)
- `isConsumed` — bool
- `actionTreeRoot` — Merkle root over all tags in the action
- `appData` — `(resourcePayload, discoveryPayload, externalPayload, applicationPayload)` blob arrays

### 5.2 Private witness

- `Resource` preimage matching `tag` (the consumed vault note)
- `label_preimage` (per §4.2)
- `pubkeys[n]` — sorted compressed pubkeys, must hash to `label_preimage.pubkey_root`
- For each signing slot `i ∈ {0..k−1}`: `(idx_i, sig_i)` with `idx_i < idx_{i+1}` (strictly increasing; ensures distinct signers)
- `change_resource` — the created resource paired with the consumed vault in compliance, carrying the unspent remainder. Must have `labelRef == consumed.labelRef` (same vault) and `quantity ≤ consumed.quantity`.
- `recipient_resources: Vec<Resource>` — created resources representing RM-internal transfers (each may have a different `labelRef`, encoding a transfer to another vault / AnomaPay user / etc.). Empty for pure EVM-withdraw mode.
- The action's full tag list, used to verify (a) the change commitment, and (b) every recipient commitment, are present in `actionTreeRoot`.

### 5.3 Constraints — consumed branch (v0.5)

1. `compute_commitment(witness_resource) == derived_commitment` and `compute_nullifier(witness_resource) == tag`.
2. `SHA256(label_preimage) == witness_resource.labelRef`.
3. `SHA256("anoma.multisig.v1.nfk-key" ‖ label_preimage) == nullifier_key`, and `SHA256(nullifier_key) == witness_resource.nullifierKeyCommitment`.
4. `|pubkeys| == label_preimage.n`, pubkeys sorted, `SHA256(pk_0 ‖ … ‖ pk_{n-1}) == label_preimage.pubkey_root`.
5. `k_witness == label_preimage.k`.
6. `idx_0 < idx_1 < … < idx_{k-1} < n`.
7. `change_resource.labelRef == consumed.labelRef`, `change_resource.quantity ≤ consumed.quantity`, `change_resource.commitment` ∈ `action_tags`.
8. For each `recipient_resources[j]`: `recipient.commitment` ∈ `action_tags`. (No constraint on `recipient.labelRef` — it can be any other vault's kind, encoding a private transfer to that holder.)
9. Walk `appData.externalPayload` blobs. For each blob whose decoded `forwarder == MULTISIG_FORWARDER`, decode the inner input as `(token, recipient, amount, expected)`, require `token == label_preimage.token_addr`, accumulate `external_sum += amount`. Blobs with other forwarder addresses are allowed but don't contribute to `external_sum` — they're a compositional escape hatch governed by other resource logics.
10. **Conservation:** `external_sum + sum(recipient.quantity) + change.quantity == consumed.quantity`. This single equation supports the three modes:
    - Pure EVM withdraw: `recipient_sum = 0`, `external_sum > 0`
    - Pure RM-internal: `external_sum = 0`, `recipient_sum > 0` (private)
    - Hybrid: both > 0
11. **Compute the in-circuit `Logic.Instance` journal digest exactly as `RiscZeroUtils.toJournal(Logic.Instance)` does:**
   ```
   journal = tag                                                     // 32 B
          ‖ (isConsumed ? 0x01000000 : 0x00000000)                  //  4 B little-endian uint32
          ‖ actionTreeRoot                                          // 32 B
          ‖ encode_payload_array(appData.resourcePayload)
          ‖ encode_payload_array(appData.discoveryPayload)
          ‖ encode_payload_array(appData.externalPayload)
          ‖ encode_payload_array(appData.applicationPayload)

   encode_payload_array(arr):
     little_endian_uint32(len(arr))
       ‖ for each ExpirableBlob b in arr:
           encode(b)   // matches RiscZeroUtils encoding exactly
   journal_digest = SHA256(journal)
   ```
   This binds every field PA's verifier checks — including all four payload categories — into the consumed-vault portion of the signature, which fully covers the EVM-side `externalPayload` blobs.
12. `recipient_commitments_sorted = sorted_ascending([recipient_resources[j].commitment for j in 0..len])`.
13. `spend_message = SHA256("anoma.multisig.v1.spend" ‖ journal_digest ‖ uint32_le(|recipients|) ‖ concat(recipient_commitments_sorted))`.
14. For each `i`: ECDSA-secp256k1-verify(`pubkeys[idx_i]`, `spend_message`, `sig_i`) with **low-s enforcement**. Signature hash is SHA256 (not keccak).

Why this binds correctly:
- The consumed vault's `journal_digest` binds the entire `appData`, including every `externalPayload` blob — so EVM-withdraw recipient + amount + token are all signed.
- The sorted `recipient_commitments` bind every RM-internal recipient — a malicious tx-assembler swapping in a different recipient resource changes its commitment, changes the sorted list, changes `spend_message`, and signature verification fails.
- The conservation constraint (#10) ensures the math closes: every wei of consumed value lands somewhere the K-of-N approved (change to themselves, recipients they signed for, or external withdrawals they signed for).

### 5.4 Constraints — created branch

1. `compute_commitment(witness_resource) == tag`.
2. `witness_resource.labelRef == SHA256(label_preimage)`.
3. `label_preimage.salt != 0`.
4. `1 ≤ label_preimage.k ≤ label_preimage.n ≤ 32`.

No signature requirement for creation. Authorization to mint a new vault note comes from whoever supplies the matching consumed resource (a fresh deposit's wrap inflow, or an old vault note's spend during rotation).

### 5.5 Journal

Commits the `Logic.Instance` fields. PA computes `sha256(instance.toJournal())` and verifies against the proof.

## 6. `MultisigForwarder.sol`

```solidity
contract MultisigForwarder is IForwarder {
    using SafeERC20 for IERC20;

    address public immutable PA;
    bytes32 public immutable WRAP_LOGIC_REF;  // outflow ephemerals run wrap_v1, not multisig_v1

    error OnlyPA();
    error WrongLogic(bytes32 expected, bytes32 actual);

    constructor(address pa, bytes32 wrapLogicRef) {
        PA = pa;
        WRAP_LOGIC_REF = wrapLogicRef;
    }

    function forwardCall(bytes32 logicRef, bytes calldata input)
        external returns (bytes memory)
    {
        if (msg.sender != PA) revert OnlyPA();
        // The carrier resource for an outflow is an ephemeral with logicRef = wrap_v1.
        // wrap_v1 is what enforces (amount == outflow.quantity), the K-of-N binding,
        // and the token/forwarder constraints. We just need to verify the call came
        // through wrap_v1 so we know those constraints have been proven.
        if (logicRef != WRAP_LOGIC_REF) revert WrongLogic(WRAP_LOGIC_REF, logicRef);
        (address token, address to, uint256 amount, bytes memory expected) =
            abi.decode(input, (address, address, uint256, bytes));
        IERC20(token).safeTransfer(to, amount);
        return expected;  // PA enforces equality via ForwarderCallOutputMismatch
    }
}
```

Properties:
- **Singleton.** One deployment per circuit version, holding ERC20s for every vault using that version. Per-vault accounting is virtual, enforced by `wrap_v1` + compliance.
- `WRAP_LOGIC_REF` is the image ID of `wrap_v1` (the carrier circuit). It is immutable; circuit upgrade = new forwarder + migration.
- No admin, rescue, or upgrade hooks.
- Reentrancy bounded by PA's `nonReentrant` on `execute`.
- Tokens transferred to the forwarder outside the wrap path are unrecoverable (acceptable; document).
- The `MultisigForwarder`'s deployed address is a global circuit constant in `wrap_v1` (and in `multisig_v1`, indirectly via the outflow appData binding). Changing the address = new circuit version + new forwarder + migration.

> **Why the singleton is safe.** The compliance circuit enforces per-kind balance. Vault A's `labelRef` defines a unique kind (vault-A-kind). To create vault-A-kind on the created side, you must consume vault-A-kind on the consumed side — which only vault A's K-of-N can authorize via `multisig_v1`. So vault A's signers cannot construct a balanced action that drains vault B's holdings out of the shared forwarder, even though both vaults' funds physically share the same address.

> **Why the `msg.sender` and `logicRef` checks are non-negotiable.** The canonical `BlockTimeForwarder` example (`contracts/src/examples/BlockTimeForwarder.sol`) intentionally has neither — its test `testFuzz_forwardCall_accepts_arbitrary_logic` proves it accepts any caller with any logicRef. PA's docstring calls forwarders "untrusted" — meaning the PA does not trust them, not the other way around. Forwarders that custody value must gate themselves; otherwise any external caller can drain them by calling `forwardCall` directly, bypassing the PA + RM entirely.

## 7. `WrapForwarder.sol`

```solidity
contract WrapForwarder is IForwarder {
    using SafeERC20 for IERC20;

    address public immutable PA;
    address public immutable MULTISIG_FORWARDER;  // canonical destination, baked in
    bytes32 public immutable WRAP_LOGIC_REF;

    error OnlyPA();
    error WrongLogic(bytes32 expected, bytes32 actual);

    enum Op { WRAP }  // outflow (unwrap) goes through MultisigForwarder directly via wrap_v1

    constructor(address pa, address multisigForwarder, bytes32 wrapLogicRef) {
        PA = pa;
        MULTISIG_FORWARDER = multisigForwarder;
        WRAP_LOGIC_REF = wrapLogicRef;
    }

    function forwardCall(bytes32 logicRef, bytes calldata input)
        external returns (bytes memory)
    {
        if (msg.sender != PA) revert OnlyPA();
        if (logicRef != WRAP_LOGIC_REF) revert WrongLogic(WRAP_LOGIC_REF, logicRef);
        (Op op, address token, address from, uint256 amount, bytes memory expected) =
            abi.decode(input, (Op, address, address, uint256, bytes));
        require(op == Op.WRAP);
        // Destination is fixed: deposits always land in the singleton MultisigForwarder.
        IERC20(token).safeTransferFrom(from, MULTISIG_FORWARDER, amount);
        return expected;
    }
}
```

Note: the `WrapForwarder` no longer takes a `destination` parameter — the destination is baked into the contract at deploy. Any `wrap_v1` proof that authorizes a deposit sends to the canonical `MultisigForwarder`. This is a slight ABI simplification from v0.3 and removes a class of "deposit to wrong destination" misconfigurations.

The `wrap_v1` circuit constrains, for the inflow side:
- `op == WRAP`
- `token == created_vault_note.label_preimage.token_addr`
- `amount == created_vault_note.quantity`
- `from` is in the appData (depositor approves `WrapForwarder` for `amount` off-chain).

For the outflow side (`wrap_v1` running against an outflow ephemeral that calls `MultisigForwarder`):
- `external_payload[0] = abi.encode(MULTISIG_FORWARDER, abi.encode(token, recipient, amount, expected), expected)`
- `external_payload.forwarder == MULTISIG_FORWARDER` (constant)
- `external_payload.token == witness_resource.labelRef → label_preimage.token_addr` (witnessed)
- `external_payload.amount == witness_resource.quantity` (witnessed)
- `witness_resource.ephemeral == true`

Without these, a malicious tx-assembler could redirect an outflow to a different recipient or a different token.

## 8. Action structures

### 8.1 Spend (single vault note → recipient + change, single token)

```
Action {
  compliance_units: [
    { consumed: vault_note_v,        created: change_note_v'        },  // multisig_v1 / multisig_v1
    { consumed: ephemeral_zero,      created: outflow_ephemeral_X   },  // wrap_v1     / wrap_v1
  ],
  logic_inputs: [
    v.proof              (multisig_v1, consumed)   // carries spend_message signature witness
    v'.proof             (multisig_v1, created)
    ephemeral_zero.proof (wrap_v1, consumed)       // trivial: ephemeral marker
    outflow_X.proof      (wrap_v1, created)        // carries externalPayload
  ],
  outflow_X.appData.externalPayload[0].blob =
    abi.encode(
      MULTISIG_FORWARDER,                                       // pinned
      abi.encode(token, recipient, X, abi.encode(true)),        // input
      abi.encode(true)                                          // expectedOutput
    )
}

quantities:  vault_note_v.quantity == change_note_v'.quantity + outflow_X.quantity
                  (Q)                       (Q - X)                (X)
```

Notes:
- The K-of-N signatures in `v.proof` bind to `spend_message = SHA256(domain ‖ v.journal_digest ‖ uint32_le(num_outflows) ‖ sorted(outflow_journal_digests))`. So they authorize the specific consumed-vault appData *and* every outflow's appData (recipient, amount, token, expected).
- `wrap_v1` enforces `outflow.quantity == external_payload.amount` and `external_payload.token == labelRef.token_addr` and `external_payload.forwarder == MULTISIG_FORWARDER`.
- Compliance enforces per-kind balance: `vault.quantity == change.quantity + outflow.quantity` for vault-A-kind.
- The change note `v'` is a vault note (non-ephemeral) of the same kind. Its `multisig_v1` created-branch proof just checks commitment integrity.
- The `ephemeral_zero` is a degenerate consumed ephemeral (quantity 0, labelRef matching) needed because compliance units pair one consumed + one created; the outflow's pairing partner.

### 8.2 Multi-recipient spend

Add additional `(ephemeral_zero, outflow_Y)` compliance units, one per recipient. Each `outflow.appData.externalPayload` carries one transfer. `multisig_v1`'s witness includes all outflow appData, and the signed `spend_message` includes their sorted journal digests. Compliance balance forces `change + sum(outflows) == vault`.

### 8.3 Deposit (depositor → new vault note)

```
Action {
  compliance_units: [
    { consumed: inflow_ephemeral, created: vault_note_v },  // wrap_v1 / multisig_v1
  ],
  logic_inputs: [
    inflow_ephemeral.proof (wrap_v1, consumed)   // carries externalPayload
    v.proof                (multisig_v1, created)
  ],
  inflow_ephemeral.appData.externalPayload[0].blob =
    abi.encode(
      WRAP_FORWARDER,                                                          // pinned
      abi.encode(WRAP, token, depositor, amount, abi.encode(true)),            // input (no destination — baked into WrapForwarder)
      abi.encode(true)                                                         // expectedOutput
    )
}
```

Depositor must `approve(WRAP_FORWARDER, amount)` before submission.

### 8.4 Rotation (old vault → new vault under different policy)

```
Action {
  compliance_units: [
    { consumed: vault_note_v_old, created: vault_note_v_new },
  ],
  // No external payload — pure RM-internal state transition.
  // K-of-N from the old set signs spend_message (no outflows present).
  // The signed message binds to the consumed vault's journal_digest, which binds appData,
  // and signers verify the new label_preimage out-of-band against the action's created
  // commitment.
}
```

The new note may differ in any field except `quantity` (compliance enforces balance) and `token_addr` (different token would be a different kind, breaking compliance balance — would need a swap, not a rotation). Common rotations:
- New signer set: change `pubkey_root`, `salt`.
- New threshold: change `k` and/or `n`.
- (`forwarder_addr` is no longer rotateable — singleton.)

For migration to a new circuit version (new `multisig_v1` image ID): consume old vault note, create new vault note with new `logicRef`. New `MultisigForwarder` and `WrapForwarder` deployed; tokens migrated by issuing a withdraw to the new forwarder address.

### 8.5 RM-internal transfer (vault A → recipient, no EVM crossing)

```
Action {
  compliance_units: [
    { consumed: vault_note_v_A,  created: change_note_v_A'   },  // multisig_v1 / multisig_v1
    { consumed: ephemeral_zero,   created: recipient_note_v_B },  // wrap_v1     / multisig_v1 (or app)
  ],
  logic_inputs: [
    v_A.proof              (multisig_v1, consumed)  // signs spend_message including recipient.commitment
    v_A'.proof             (multisig_v1, created)
    ephemeral_zero.proof   (wrap_v1, consumed)
    recipient_note.proof   (logic of recipient's choosing — typically the recipient's own multisig_v1 created branch, or AnomaPay's TokenTransferPersistent logic)
  ],
  // NO externalPayload anywhere — nothing touches MultisigForwarder.
}

quantities:  vault_note_v_A.quantity == change_note_v_A'.quantity + recipient_note_v_B.quantity
                  (Q)                       (Q - X)                       (X)
```

Notes:
- The recipient resource may be controlled by anything: another `multisig_v1` vault (recipient holds their own K-of-N), an AnomaPay user's `TokenTransferPersistent` logic, or any other RM logic. Vault A's signers don't need to know the recipient's logic — they only sign over the recipient's commitment, which fully binds the recipient's resource preimage.
- Discoverability: vault A's coordinator encrypts the recipient note's preimage to the recipient's discovery key (standard `discoveryPayload` channel) so the recipient can find the note off-chain.
- Privacy: PA emits no `ExternalPayload` event for this action (there are none). The only chain-visible artifacts are the new commitment in the merkle tree and the consumed vault's nullifier. An observer cannot determine recipient identity, transferred amount, or even the token from chain state alone.
- Compliance balance: the (`ephemeral_zero`, `recipient_note`) unit has zero kind delta if `recipient.labelRef == vault_A.labelRef` (same kind). For cross-kind transfers (recipient is a different vault), the action needs a wrap pair to balance both kinds — same shape as the deposit pattern in §8.3, just composed inside one action.

### 8.6 Hybrid (RM-internal + EVM withdraw in one signature batch)

Combine §8.1 and §8.5 in a single action: K-of-N signs over a single `spend_message` that binds both the consumed vault's `appData` (covering EVM `externalPayload` blobs) AND the sorted recipient commitments. Conservation forces `external_sum + recipient_sum + change == consumed`.

## 9. Off-chain coordinator

### 9.1 Components

- **Note discovery**: scan `DiscoveryPayload` events; decrypt entries addressed to the local signer's discovery key; maintain unspent vault notes per labelRef.
- **Action assembly**: construct the candidate `Action`; compute `actionTreeRoot`, `external_digest`, and `msg`.
- **Signature collection**: out-of-band channel (Signal, signer HTTP API, hardware-wallet signer pool); present each signer with the full action, not just `msg`.
- **Proof generation**: run `multisig_v1` and `wrap_v1` guests; run canonical compliance circuit per unit; run canonical aggregation circuit.
- **Pre-flight**: call `ProtocolAdapter.simulateExecute(transaction, false)`. The PA reverts with `Simulated(uint256 gasUsed)`. Use this to gas-cost the tx and to surface any logic-proof / forwarder-output mismatch before wasting submission gas. (Pass `true` for the second arg only when the off-chain prover is still iterating and you want to skip RISC Zero verification — never for production submission paths.)
- **Submission**: call `ProtocolAdapter.execute(transaction)`.

### 9.2 Signer UI requirements (MUST surface, before signing)

- Specific consumed nullifier(s) — defends against wrong-note signing when multiple notes share a labelRef.
- For every `externalPayload` blob: forwarder address, full decoded calldata (for `MultisigForwarder` calls: `token`, `recipient`, `amount`).
- For every created note: labelRef equality with the consumed note (or, on rotation, the new `label_preimage` in plaintext including new pubkey set, k, n, forwarder address, salt).
- The `actionTreeRoot` being signed.
- A clear visual diff between the consumed and created notes (quantity changes, policy changes).

If the UI hides any of these, the signer is signing blind and the protocol's guarantees collapse to "trust the coordinator."

## 10. Threat model

### 10.1 What this protects against

- On-chain compromise of signer set discovery (pubkeys committed, not revealed).
- Authorization replay across actions or across vault notes (bound by `spend_message`, which binds `actionTreeRoot` via `journal_digest`).
- Forwarder address substitution (`MULTISIG_FORWARDER` is a circuit constant baked into the image ID).
- EVM-side recipient/amount/token substitution (signed via `journal_digest` which commits the entire `appData.externalPayload`).
- RM-internal recipient substitution (recipient commitments fold into `spend_message` — swapping a recipient changes the sorted set, changes `spend_message`, fails signature verification).
- Conservation breaks (sum of change + recipients + external must equal consumed; circuit rejects otherwise).
- Cross-vault drain. The shared forwarder physically holds all vaults' tokens, but compliance per-kind balance prevents vault A's K-of-N from constructing a balanced action that touches vault B's funds — moving any vault-B-kind requires consuming vault-B-kind, which only vault B's signers can authorize via their `multisig_v1` proof.
- Submitter substitution (PA verifies proof; submitter doesn't matter).
- **Activity privacy under RM-internal mode.** Recipient identity, amount, and token are not visible to chain observers — only commitment updates are public.

### 10.2 What this does NOT protect against

- **Activity privacy.** Recipient, amount, token, and forwarder address are public via `ExternalPayload` events.
- **Front-running** of public-mempool submission.
- **Coercion of K signers.**
- **PA owner permanently disabling all spends** (T1).
- **Loss of K signers' keys** — vault is bricked, same as Safe.
- **Loss of `label_preimage`** — funds discoverable but not spendable.
- **Wrong-note signing** if the coordinator UI hides nullifiers.
- **Stuck funds** for tokens transferred to the forwarder outside the wrap path.
- **Sticky policy** — change note can have a different labelRef; relies on signer review (Q3).
- **Same-circuit-version drain via collusion across vaults.** If K-of-N of vault A and K-of-N of vault B both collude, they can jointly construct multi-action transactions that move funds across vaults in ways neither alone could. This is by definition (combined K signers from two vaults = two compromised vaults), not a new attack.
- **Activity privacy under EVM-withdraw mode.** Recipient/amount/token are public via `ExternalPayload` and `IERC20.Transfer` events. This is an EVM-boundary constraint — the standard ERC-20 `Transfer` event is mandatory. Use RM-internal mode for private transfers (§8.5).

## 11. Open design questions

| # | Question | v1 default |
|---|---|---|
| Q1 | Signature scheme: secp256k1 (EVM key reuse) or Ed25519 (faster verify)? | secp256k1. Reconsider after RISC0 cycle profiling. |
| Q2 | Fixed-array signer set or Merkle-witness for large N? | Fixed array, N ≤ 32. |
| Q3 | Should change note's `labelRef` be pinned to consumed note's in-circuit? | No. Allows rotation-in-spend. Documented UX hazard. |
| Q4 | Multiple consumed vault notes per action (consolidation)? | Allowed. Each carries its own logic proof. Single `actionTreeRoot` binding. |
| Q5 | Canonical PA or fork? | Canonical for v1 testnet; fork before mainnet. |
| Q6 | Discovery payload encryption scheme? | Out of v1 scope. NaCl box to per-signer discovery key, ephemeral key in `randSeed`. |
| Q7 | RISC0 cycle budget per ECDSA verify, full proving cost K=5, N=32? | TBD — block on actual profiling before committing to circuit shape. |

## 12. Test plan

### Unit — circuit (`multisig_v1`)

- Hand-rolled witnesses for: K=1, K=2, K=N.
- Negative: malformed sig, low-s violation (high-s rejected), duplicate index, out-of-range index, wrong forwarder address in external payload, label preimage mismatch, pubkey set unsorted, `n != |pubkeys|`, `k > n`, `salt == 0` (created branch).

### Unit — circuit (`wrap_v1`)

- Wrap with correct destination, token, amount.
- Negative: wrong destination forwarder, wrong token, quantity mismatch.

### Unit — Solidity (Foundry)

- `MultisigForwarder`: caller != PA reverts; wrong logicRef reverts; `safeTransfer` fail propagates.
- `WrapForwarder`: same checks plus `transferFrom` insufficient-allowance propagation.

### Integration

- Full deposit → spend → rotation cycle against a local PA deploy. Mirror the harness in `anoma/pa-evm`'s `example-tx-generation/`.
- Multi-recipient spend with three external payloads, three outflow pairs, single signature batch.
- Rotation that changes the forwarder address, followed by a spend that transfers funds from old forwarder to new (separate pre-step).

### Adversarial

- Replay a previously executed transaction (must revert via duplicate nullifier in `NullifierSet`).
- Substitute the EVM recipient in `externalPayload` (must fail signature verification — `journal_digest` covers `appData`).
- Substitute external token or amount (must fail conservation or token-mismatch constraint).
- **RM-internal: substitute the recipient resource** (must fail signature verification — recipient commitment is in `spend_message`).
- **RM-internal: omit a recipient resource that signers approved** (must fail — the omitted commitment was in the original `spend_message`).
- **RM-internal: tamper any quantity to break conservation** (must fail with `ConservationBroken`).
- Cross-vault drain attempt: vault A's K-of-N signs an action that creates outflows of vault-B-kind. Compliance must reject (vault-B-kind cannot be created without consuming vault-B-kind, and vault A's K-of-N cannot consume vault-B notes since only vault B's `multisig_v1` proof can nullify them).
- Submit a transaction during PA pause (must revert via `whenNotPaused`).

## 13. v2 candidates (out of scope)

- Confidential EVM withdrawals (Aztec-style mixer pool or shielded ERC-20 wrapper) — needed only for activity-private transfers to *external EVM addresses*. RM-internal transfers are already private (§8.5).
- Composition with intent-style logics (price oracles, time locks) in the same action.
- Schnorr signature aggregation in-circuit (K signers private behind a single aggregate sig).
- Native ETH support via a payable wrapper forwarder.
- Relayer / fee-payment mechanism (likely a separate fee-payment resource pattern).
- Token allowlists per vault (an extra label-bound constraint).
- Dynamic signer-set Merkle trees for N > 32.
- Migration tool: v1 → v2 vault note transition action.
