# Historical identities and independent exits in MID LayerTree

**Status:** research hardening of the experimental MID implementation, based on
[Rubin's Sapio PR #314](https://github.com/sapio-lang/sapio/pull/314),
commit `616cdba38bc9102d0994eb5fd5aa4db88508d8f4`.

The proof-bearing Bitcoin Script verifies the *current* Merkle-sum state.
This is enough to enforce the value, membership, payout, lease and successor
rules for a single transition. A historical fact such as "this (owner, nonce)
already existed and was spent" is absent from that current root.

## Executable regression: old voucher revived by readmission

The integration test
`historical_owner_nonce_reuse_revives_a_signed_voucher_in_the_real_mid_guest`
uses the actual distributed MID WASM evaluator. It prepares a valid BIP340
voucher in the initial state, authorizes an UPDATE to a different
`(owner_key, nonce)`, and authorizes a second UPDATE that restores the original
leaf byte for byte. The original voucher then authorizes a CLAIM against
the new Bitcoin outpoint.

Both intermediate UPDATEs use current owner and operator signatures. The
old voucher signature remains unchanged. The transition is meaningful as an
*adversarial application scenario*: an issuer may intend the restored position
to be a fresh allocation, while the holder of a previously issued voucher
can still spend it because the signed message has returned.

The underlying [LayerTree documentation](LAYERTREE.md) already identifies
this risk. This fork adds a direct oracle regression rather than claiming a
new consensus vulnerability. The test proves the consequence *within the
experimental emulator* and its explicitly stated oracle trust model.

## Application-side prevention

`sapio_contrib::contracts::layertree::LineageGuard` provides a serializable
history of every observed owner/nonce identity, bound to a particular
`tree_id`, tree depth and previous state root.

The guard checks candidate successor trees before any signature is released:

1. Any newly placed `(owner_key, nonce)` must be absent from **all recorded
   history**, including exited and overwritten leaves.
2. An identity retained in the same slot may only increase `seq`. Keeping
   `seq` unchanged permits **amount-only** updates, because vouchers omit the
   amount. Any change to voucher-bound fields requires a sequence increase.
3. The predecessor must equal the guard's current state root. An obsolete
   signing session cannot silently start from an earlier tree.
4. The successor is recorded only after all checks succeed, preserving state
   on rejection.

The example helper `prepare_step_guarded` invokes the check in its
**unsigned witness-planning pass**, before producing transaction authority
signatures. This is an opt-in integration example. A deployment must use the
guard at *every* admission, transfer, rewrite, payout and signing boundary.

Minimal use:

```rust
use sapio_contrib::contracts::layertree::LineageGuard;

// Only at initial creation. Restore durable guard state thereafter.
let mut guard = LineageGuard::bootstrap(contract.config().tree_id, &initial);

// While holding the wallet's exclusive signing and state lock:
guard.check(contract.config().tree_id, &current, &proposed)?;
// Construct the real spend, obtain signatures, checkpoint the chain intent,
// and atomically persist the accepted successor together with the guard.
guard.advance(contract.config().tree_id, &current, &proposed)?;
```

The two calls form a logical guarded transaction. The actual wallet must
serialize signing sessions, resolve competing branch confirmation, and keep
the guard and signed spend intent in crash-consistent durable storage.
Do not bootstrap a new empty history when restoring a preexisting tree.

### What it does *not* enforce

- Bitcoin cannot consult this off-chain history, and the MID host cannot
  independently enforce a persistent nonce tombstone. Operators or members
  that bypass the guard can still create a voucher-replayable state.
- An attacker who rolls back **both** the wallet database and guard can
  defeat the predecessor check. An independently trusted monotonic
  checkpoint or confirmation history is needed.
- A dishonest or unavailable Sapio oracle remains a separate trust
  dependency. The current experimental MID covenant is checked by WASM,
  while Bitcoin validates the resulting Taproot signatures.
- This does not implement a SaplingOS VTXO, an Ark server, AWS Nitro
  attestation, Lightning networking or independent layer-three exit
  mechanisms. The new two-holder test exercises LayerTree's shared
  on-chain **UTXO** and member leaves, not nested ownership of an Ark VTXO.

## Two-holder exit property

`two_members_exit_sequentially_without_either_coparticipants_signature`
funds two member leaves with 60,000 and 40,000 satoshis. Alice's
`EXIT_1` pays exactly her 60,000 sats and leaves a live 40,000-sat pool.
Bob then uses his own `EXIT_1`, receiving 40,000 sats and closing the
shared tree. Each transaction is signed by the member whose leaf exits,
with a separate fee sponsor. The oracle still co-signs the native
wrapper for both spends.

This makes the dependency precise: exits are independent of the other
**member's signature** and the operator's signature, conditional on a
cooperative honest oracle and the upstream covenant assumptions.

## Reproduction

```sh
cargo test --locked -p sapio-contrib --lib lineage
cargo test --locked -p sapio_integration_tests --test layertree \
    historical_owner_nonce_reuse_revives_a_signed_voucher_in_the_real_mid_guest
cargo test --locked -p sapio_integration_tests --test layertree \
    two_members_exit_sequentially_without_either_coparticipants_signature
cargo fmt --all -- --check
```

The full existing workflow also runs funded transitions through Bitcoin
Core regtest, but these newly added tests are offline WASM execution tests.
They do not prove independent Ark/VTXO recoverability.

## Next proof obligations for a shared Ark VTXO

The [SaplingOS recovery implementation](https://github.com/stutxo/saplingos/blob/b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d/sdk/src/sapio/recovery.rs)
has pre-signed exact-beneficiary exit bundles with explicit readiness states.
For a shared Ark VTXO, the application should additionally prove that:

- every participant can independently verify the committed beneficiary
  amount and script against the **same** canonical parent backing;
- recovery availability survives Sapio/Ark disappearance, concurrent
  successors and the VTXO expiry window;
- a historical claim or stale recipient authorization cannot double-count
  the same capital or redirect the current beneficiary share; and
- both the direct cooperative signing flow and every saved emergency
  branch preserve the contract-specific allocation.

These requirements should be tested against a real SaplingOS-backed
transaction graph before attributing any property to Matthew Vuk's
unavailable GitLab implementation.
