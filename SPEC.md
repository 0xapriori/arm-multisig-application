# Anoma Multi-Sig on `pa-evm`

**Version:** 0.4
**Target:** canonical [`anoma/pa-evm`](https://github.com/anoma/pa-evm) at PA `v1.1.0`, RISC Zero verifier selector `0x73c457ba`.
**Status:** design — partial implementation

## 1. Scope

A k-of-n multi-signature vault for ERC20 tokens on EVM where:

- Vault state is RM resources (a "kind" derived from `labelRef`), not a Solidity account.
- Signer set is committed in `labelRef` but not publicly revealed.
- Spend authorization is a RISC0 logic proof verified via the existing `ProtocolAdapter`.
- A single `MultisigForwarder` instance holds the ERC20s of *all* vaults using this circuit; per-vault accounting is virtual (RM-native), enforced by the compliance circuit's per-kind balance + `wrap_v1`'s amount binding.
- Movement is atomic and proof-gated by the PA.

### Non-goals (v1)

- Activity-level privacy. Recipient and amount of every spend are public events.
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
| T3 | Aggregation circuit verifying key is hardcoded (`0x213b…0827`). | Inherent to `pa-evmx`. |
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
│   (off-chain)  │                    │   (pa-evmx)      │
└────────────────┘                    └────────┬─────────┘
        ▲                                      │ forwardCall(logicRef, input)
        │ collect K signatures                 │ msg.sender == PA
        │                                      ▼
┌────────────────┐                    ┌──────────────────┐
│  N signers     │                    │ MultisigForwarder│ <- one per vault
│ (off-chain)    │                    │  (holds ERC20s)  │
└────────────────┘                    └──────────────────┘
                                            ▲
                                            │ on deposit
                                      ┌─────┴──────┐
                                      │WrapForwarder│ <- shared
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

- `Resource` preimage matching `tag`
- `label_preimage` (per §4.2)
- `pubkeys[n]` — sorted compressed pubkeys, must hash to `label_preimage.pubkey_root`
- For each signing slot `i ∈ {0..k−1}`: `(idx_i, sig_i)` with `idx_i < idx_{i+1}` (strictly increasing; ensures distinct signers)
- For each outflow ephemeral `j` in the action that has `labelRef == witness_resource.labelRef`:
  - the outflow's `commitment` (so the circuit can verify membership in `actionTreeRoot`)
  - the outflow's `appData` (so the circuit can compute its journal digest and include it in the signed message)
- The action's full tag list (so the circuit can reconstruct `actionTreeRoot` and prove outflow commitments are members)

### 5.3 Constraints — consumed branch

1. `compute_commitment(witness_resource) == derived_commitment` and `compute_nullifier(witness_resource) == tag` (per RM nullifier construction; also gives the circuit authenticated access to all resource fields).
2. `SHA256(label_preimage) == witness_resource.labelRef`.
3. `SHA256("anoma.multisig.v1.nfk-key" ‖ label_preimage) == nullifier_key`, and `SHA256(nullifier_key) == witness_resource.nullifierKeyCommitment`.
4. `|pubkeys| == label_preimage.n`, pubkeys sorted, `SHA256(pk_0 ‖ … ‖ pk_{n-1}) == label_preimage.pubkey_root`.
5. `k_witness == label_preimage.k`.
6. `idx_0 < idx_1 < … < idx_{k-1} < n`.
7. **Compute the in-circuit `Logic.Instance` journal digest exactly as `RiscZeroUtils.toJournal(Logic.Instance)` does:**
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
   This binds *every* field PA's verifier checks — including all four payload categories — into the consumed-vault portion of the signature.
8. **Reconstruct `actionTreeRoot`** from the witnessed action tag list (`MerkleTree.computeRoot`); check it equals the public `actionTreeRoot`. This authenticates the witnessed tag list.
9. **For each witnessed outflow ephemeral `j`:** verify its `commitment` is in the witnessed tag list. Compute `outflow_journal_digest_j = SHA256(toJournal(Logic.Instance{tag: outflow.commitment, isConsumed: false, actionTreeRoot, appData: outflow.appData}))`.
10. `outflow_digests = sorted_ascending(outflow_journal_digest_j)`. Sorting domain-separates from witness ordering.
11. `spend_message = SHA256("anoma.multisig.v1.spend" ‖ journal_digest ‖ uint32_le(|outflows|) ‖ concat(outflow_digests))`.
12. For each `i`: ECDSA-secp256k1-verify(`pubkeys[idx_i]`, `spend_message`, `sig_i`) with **low-s enforcement**. The signature curve hash is SHA256 (not keccak).

Why bind the consumed journal AND the outflow journals: `actionTreeRoot` commits to all tags but not to `appData`. The consumed vault's `journal_digest` binds its own `appData`. But the actual *external transfers* live in the outflow ephemerals' `externalPayload` (so `wrap_v1` can constrain `external_payload.amount == outflow.quantity`). Without including outflow `appData` digests in the signed message, a prover holding K signatures could swap recipients/amounts on the outflows (the proof would still verify because their amounts only need to match the outflow quantities, which are themselves arbitrary). Including the outflow digests makes the signature cover the entire spend authorization.

The amount-binding chain is now:
- `wrap_v1` constrains `external_payload.amount == outflow.quantity` and `external_payload.token == labelRef.token_addr` and `external_payload.forwarder == MULTISIG_FORWARDER`.
- Compliance per-kind balance forces `sum(outflow.quantity) + sum(change.quantity) == consumed.quantity` for vault-A-kind.
- Signers see all outflows + change in the coordinator UI before signing; `spend_message` binds them.
- Therefore the only way the K-of-N's authorization succeeds is if the action's actual external transfers equal what they signed for, denominated in the right token, going to a forwarder that holds the vault's funds.

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
- Forwarder address substitution (`MULTISIG_FORWARDER` is a circuit constant; `wrap_v1` rejects any other address).
- Recipient, amount, or token substitution on outflows (signed via outflow journal digest in `spend_message`; amount/token bound in-circuit by `wrap_v1`).
- Cross-vault drain. The shared forwarder physically holds all vaults' tokens, but compliance per-kind balance prevents vault A's K-of-N from constructing a balanced action that touches vault B's funds — moving any vault-B-kind requires consuming vault-B-kind, which only vault B's signers can authorize via their `multisig_v1` proof.
- Submitter substitution (PA verifies proof; submitter doesn't matter).

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

- Full deposit → spend → rotation cycle against a local PA deploy. Mirror the harness in `pa-evmx/example-tx-generation/`.
- Multi-recipient spend with three external payloads, three outflow pairs, single signature batch.
- Rotation that changes the forwarder address, followed by a spend that transfers funds from old forwarder to new (separate pre-step).

### Adversarial

- Replay a previously executed transaction (must revert via duplicate nullifier in `NullifierSet`).
- Substitute the forwarder address in an outflow's external payload (must fail `wrap_v1` constraint — `MULTISIG_FORWARDER` is a circuit constant).
- Substitute the recipient in an outflow's external payload (must fail signature verification — outflow journal digest is in `spend_message`).
- Substitute outflow amount or token (must fail `wrap_v1` constraints `amount == quantity`, `token == labelRef.token_addr`).
- Cross-vault drain attempt: vault A's K-of-N signs an action that creates outflows of vault-B-kind. Compliance must reject (vault-B-kind cannot be created without consuming vault-B-kind, and vault A's K-of-N cannot consume vault-B notes since only vault B's `multisig_v1` proof can nullify them).
- Add an extra outflow not signed by K-of-N: signature must fail because `spend_message` includes ALL outflows' journal digests sorted; an extra outflow changes the sorted set.
- Submit a transaction during PA pause (must revert via `whenNotPaused`).

## 13. v2 candidates (out of scope)

- Encrypted external payloads (activity privacy) via a confidential-transfer forwarder.
- Composition with intent-style logics (price oracles, time locks) in the same action.
- Schnorr signature aggregation in-circuit (K signers private behind a single aggregate sig).
- Native ETH support via a payable wrapper forwarder.
- Relayer / fee-payment mechanism (likely a separate fee-payment resource pattern).
- Token allowlists per vault (an extra label-bound constraint).
- Dynamic signer-set Merkle trees for N > 32.
- Migration tool: v1 → v2 vault note transition action.
