//! Wallet-side historical identity and voucher-generation guard for MID LayerTree.
//!
//! The covenant proves *current* Merkle membership. It cannot see earlier
//! identities removed from that root. Re-admitting the same (owner, nonce)
//! can revive an old bearer voucher. Likewise, reverting voucher-bound leaf
//! fields without advancing `seq` can restore a previously signed message.
//!
//! This helper is a deliberately separate, application-enforced admission
//! policy. Persist it atomically with the accepted state; reject old snapshots;
//! bind it to a confirmed outpoint or another independently trusted monotonic
//! checkpoint. The Sapio emulation oracle does NOT enforce this history.
//! Rebuilding the guard from only the current tree loses the tombstones.
//!
//! The code also cannot defeat signer denial of service, a dishonest oracle,
//! historical equivocation, or a rollback of both this guard and the wallet DB.

use super::tree::{Leaf, Node, Tree};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The identity that vouchers can address across time within one tree lineage.
type Identity = ([u8; 32], u32);

fn identity(leaf: &Leaf) -> Identity {
    (leaf.owner_key.serialize(), leaf.nonce)
}

/// Complete local history needed to reject an identity recycled after it exits.
///
/// The `tree_id` must be independently pinned to the creation outpoint. The
/// `root` is the exact preceding tree state, so applying a transition based
/// on a stale predecessor fails even when the successor looks individually
/// valid. A serialized guard is sensitive wallet data, not an attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageGuard {
    tree_id: [u8; 32],
    depth: u8,
    root: Node,
    ever_seen: BTreeSet<Identity>,
}

impl LineageGuard {
    /// Bootstrap a NEW lineage, before accepting its first funding commitment.
    ///
    /// For an existing lineage, restore the prior durable guard instead.
    pub fn bootstrap(tree_id: [u8; 32], initial: &Tree) -> Self {
        let ever_seen = initial.leaves().map(|(_, leaf)| identity(leaf)).collect();
        Self {
            tree_id,
            depth: initial.depth(),
            root: initial.root(),
            ever_seen,
        }
    }

    /// Return the immutable identifier of this tree lineage.
    pub fn tree_id(&self) -> [u8; 32] {
        self.tree_id
    }

    /// Return the committed root of the latest acknowledged state.
    pub fn root(&self) -> Node {
        self.root
    }

    /// Count every historically occupied owner/nonce pair, including exits.
    pub fn historical_identities(&self) -> usize {
        self.ever_seen.len()
    }

    /// Check a candidate successor without changing the guard.
    ///
    /// A source identity may stay at its existing position and increase its
    /// voucher generation. At equal sequence, only its amount may change:
    /// `voucher_message` excludes amount and commits to all other leaf bytes.
    /// A previously seen identity may never enter at a new position, including
    /// after complete withdrawal and later re-admission.
    pub fn check(
        &self,
        tree_id: [u8; 32],
        current: &Tree,
        successor: &Tree,
    ) -> Result<(), &'static str> {
        if tree_id != self.tree_id {
            return Err("wrong LayerTree lineage identifier");
        }
        if current.depth() != self.depth || successor.depth() != self.depth {
            return Err("LayerTree lineage depth changed");
        }
        if current.root() != self.root {
            return Err("stale or unrelated LayerTree predecessor");
        }

        for (position, next) in successor.leaves() {
            let id = identity(next);
            let unchanged_identity = current.leaf(position).filter(|prior| identity(prior) == id);
            if let Some(prior) = unchanged_identity {
                if next.seq < prior.seq {
                    return Err("LayerTree voucher sequence regressed");
                }
                // The voucher signs bytes [8..116], not the amount. Reusing
                // those bytes after changing them revives a prior voucher.
                if next.seq == prior.seq && next.serialize()[8..] != prior.serialize()[8..] {
                    return Err("voucher-bound leaf fields changed without sequence advance");
                }
            } else if self.ever_seen.contains(&id) {
                return Err("historical LayerTree owner/nonce identity reused");
            }
        }
        Ok(())
    }

    /// Advance the in-memory state for a checked successor.
    ///
    /// A coordinator must durably write a pending transition, its consumed
    /// identities and the signed-spend intent BEFORE releasing an authority
    /// signature, then reconcile which branch actually confirms. This method
    /// alone performs no disk transaction or on-chain conflict resolution.
    pub fn advance(
        &mut self,
        tree_id: [u8; 32],
        current: &Tree,
        successor: &Tree,
    ) -> Result<(), &'static str> {
        self.check(tree_id, current, successor)?;
        for (_, leaf) in successor.leaves() {
            self.ever_seen.insert(identity(leaf));
        }
        self.root = successor.root();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tree::{NUMS, SEQ_FINAL};
    use super::*;
    use bitcoin::secp256k1::XOnlyPublicKey;

    fn member(nonce: u32, seq: u32, amount: u64) -> Leaf {
        let key = XOnlyPublicKey::from_slice(&NUMS).unwrap();
        Leaf {
            amount,
            exit_key: key,
            owner_key: key,
            evictor_key: key,
            evict_after: 200,
            nonce,
            seq,
        }
    }

    fn seeded() -> (Tree, LineageGuard) {
        let mut initial = Tree::new(2).unwrap();
        initial.set(0, Some(member(9, 0, 20_000))).unwrap();
        let guard = LineageGuard::bootstrap([7; 32], &initial);
        (initial, guard)
    }

    #[test]
    fn tombstones_survive_exit_and_serialization() {
        let (original, mut guard) = seeded();
        let mut exited = original.clone();
        exited.set(0, None).unwrap();
        guard.advance([7; 32], &original, &exited).unwrap();
        assert_eq!(guard.historical_identities(), 1);
        let stored = serde_json::to_string(&guard).unwrap();
        let mut restored: LineageGuard = serde_json::from_str(&stored).unwrap();
        assert_eq!(restored.root(), exited.root());

        let mut replay = exited.clone();
        replay.set(0, Some(member(9, 0, 20_000))).unwrap();
        let snapshot = restored.clone();
        assert_eq!(
            restored.advance([7; 32], &exited, &replay),
            Err("historical LayerTree owner/nonce identity reused")
        );
        assert_eq!(restored, snapshot);
        assert_eq!(
            guard.check([8; 32], &exited, &replay),
            Err("wrong LayerTree lineage identifier")
        );
    }

    #[test]
    fn update_away_and_back_cannot_reuse_an_old_identity() {
        let (original, mut guard) = seeded();
        let mut changed = original.clone();
        changed.set(0, Some(member(10, 0, 20_000))).unwrap();
        guard.advance([7; 32], &original, &changed).unwrap();

        let mut recycled = changed.clone();
        recycled.set(0, original.leaf(0).cloned()).unwrap();
        assert_eq!(
            guard.check([7; 32], &changed, &recycled),
            Err("historical LayerTree owner/nonce identity reused")
        );
        // Re-admission with a fresh nonce is permitted.
        recycled.set(0, Some(member(11, 0, 20_000))).unwrap();
        guard.advance([7; 32], &changed, &recycled).unwrap();
        assert_eq!(guard.historical_identities(), 3);
    }

    #[test]
    fn unchanged_identity_allows_amount_only_topups_and_monotonic_sequences() {
        let (initial, mut guard) = seeded();
        let mut topped = initial.clone();
        topped.set(0, Some(member(9, 0, 30_000))).unwrap();
        guard.advance([7; 32], &initial, &topped).unwrap();

        let mut next = topped.clone();
        let mut new_member = member(9, 1, 30_000);
        new_member.evict_after = 250;
        next.set(0, Some(new_member)).unwrap();
        guard.advance([7; 32], &topped, &next).unwrap();

        let mut regressed = next.clone();
        regressed.set(0, Some(member(9, 0, 30_000))).unwrap();
        assert_eq!(
            guard.check([7; 32], &next, &regressed),
            Err("LayerTree voucher sequence regressed")
        );

        let mut finalized = next.clone();
        let mut leaf = next.leaf(0).unwrap().clone();
        leaf.seq = SEQ_FINAL;
        finalized.set(0, Some(leaf)).unwrap();
        guard.advance([7; 32], &next, &finalized).unwrap();
    }

    #[test]
    fn changing_voucher_bound_fields_at_same_seq_requires_a_bump() {
        let (original, mut guard) = seeded();
        let mut changed = original.clone();
        let mut member = original.leaf(0).unwrap().clone();
        member.evict_after += 1;
        changed.set(0, Some(member)).unwrap();
        assert_eq!(
            guard.advance([7; 32], &original, &changed),
            Err("voucher-bound leaf fields changed without sequence advance")
        );
        assert_eq!(guard.root(), original.root());
    }

    #[test]
    fn moving_an_identity_or_forking_from_a_stale_root_fails() {
        let (initial, mut guard) = seeded();
        let mut moved = initial.clone();
        moved.set(0, None).unwrap();
        moved.set(1, initial.leaf(0).cloned()).unwrap();
        assert_eq!(
            guard.check([7; 32], &initial, &moved),
            Err("historical LayerTree owner/nonce identity reused")
        );

        let mut advanced = initial.clone();
        advanced.set(1, Some(member(10, 0, 10_000))).unwrap();
        guard.advance([7; 32], &initial, &advanced).unwrap();
        assert_eq!(
            guard.check([7; 32], &initial, &advanced),
            Err("stale or unrelated LayerTree predecessor")
        );
        let mut wrong_depth = Tree::new(3).unwrap();
        wrong_depth.set(0, Some(member(11, 0, 10_000))).unwrap();
        assert_eq!(
            guard.check([7; 32], &advanced, &wrong_depth),
            Err("LayerTree lineage depth changed")
        );
    }

    #[test]
    fn rejecting_an_entire_batch_does_not_consume_new_identities() {
        let (initial, mut guard) = seeded();
        let mut first = initial.clone();
        first.set(1, Some(member(10, 0, 1_000))).unwrap();
        guard.advance([7; 32], &initial, &first).unwrap();
        let mut next = first.clone();
        next.set(1, None).unwrap();
        next.set(2, Some(member(10, 0, 1_000))).unwrap();
        let saved = guard.clone();
        assert!(guard.advance([7; 32], &first, &next).is_err());
        assert_eq!(guard, saved);
    }
}
