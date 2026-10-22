//! Durable, single-writer signing reservations for an emulated MID LayerTree.
//!
//! The in-memory `LineageGuard` checks historical voucher identities.
//! A signing coordinator must ALSO save its next intent before signatures
//! escape. Otherwise a crash or competing signer can reauthorize an obsolete
//! tree state. This module provides a conservative write-ahead reservation
//! and atomic local-file checkpoint for a trusted single-host coordinator.
//!
//! A reservation is intentionally sticky: an unconfirmed or failed signing
//! attempt still blocks further signing until its fate is reconciled. There
//! is no unsafe "forget pending" API. Reload the journal after a crash.
//!
//! The caller must establish transaction confirmation independently. File
//! locking and sync do not provide hardware-backed rollback protection,
//! distributed fencing, Bitcoin validation, a Sapio oracle, or independent
//! member exit availability.

use super::lineage::LineageGuard;
use super::tree::{tree_spk, Node, Tree};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TMP: AtomicU64 = AtomicU64::new(0);
const JOURNAL_VERSION: u32 = 1;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, reason)
}

/// Exact unsigned Bitcoin transaction committed before releasing any signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningReservation {
    /// Exact input outpoint the prospective transaction spends.
    pub input: OutPoint,
    /// SegWit transaction ID, fixed by unsigned input and output bytes.
    pub txid: Txid,
    /// Previous Merkle-sum commitment.
    pub before: Node,
    /// New Merkle-sum commitment, including all member allocations.
    pub after: Node,
}

/// Persistable coordinator journal for one canonical shared output.
///
/// An accepted chain transition advances both the canonical root and outpoint.
/// Until that happens, one outstanding reservation monopolizes the signing
/// lineage, preventing a second conflicting authorization. The current and
/// proposed member trees are supplied by the wallet and verified by root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageJournal {
    version: u32,
    guard: LineageGuard,
    outpoint: OutPoint,
    script_root: [u8; 32],
    pending: Option<SigningReservation>,
}

impl LineageJournal {
    /// Start a new tree with an independently verified funded Bitcoin outpoint.
    ///
    /// For an existing lineage load its saved journal, retaining every
    /// historical tombstone. A fresh bootstrap is appropriate only at genesis.
    pub fn bootstrap(
        tree_id: [u8; 32],
        script_root: [u8; 32],
        outpoint: OutPoint,
        initial: &Tree,
    ) -> Result<Self, &'static str> {
        if initial.root().sum == 0 {
            return Err("cannot bootstrap an unfunded LayerTree");
        }
        tree_spk(initial.root().hash, script_root)?;
        Ok(Self {
            version: JOURNAL_VERSION,
            guard: LineageGuard::bootstrap(tree_id, initial),
            outpoint,
            script_root,
            pending: None,
        })
    }

    /// The currently canonical coin from which a new transaction must spend.
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Authenticated history root of the last locally acknowledged spend.
    pub fn root(&self) -> Node {
        self.guard.root()
    }

    /// Read the entire outstanding authorization, if any.
    pub fn pending(&self) -> Option<&SigningReservation> {
        self.pending.as_ref()
    }

    /// Return the immutable per-lineage historical identity checker.
    pub fn guard(&self) -> &LineageGuard {
        &self.guard
    }

    /// Check a candidate Bitcoin transaction and reserve it before signing.
    ///
    /// Signing callers must first durably persist the updated journal.
    /// The spend's *first* input must be the canonical pool coin. Its first
    /// output must commit to the exact next state, or be the terminal zero
    /// output. Coin funding and the confirmed chain are validated externally.
    pub fn reserve(
        &mut self,
        current: &Tree,
        next: &Tree,
        prevout: &TxOut,
        transaction: &Transaction,
    ) -> Result<Txid, &'static str> {
        if self.pending.is_some() {
            return Err("LayerTree signing reservation already outstanding");
        }
        if self.guard.root().sum == 0 {
            return Err("LayerTree lineage already closed");
        }
        self.guard.check(self.guard.tree_id(), current, next)?;
        let input = transaction
            .input
            .first()
            .ok_or("transaction has no LayerTree input")?;
        if input.previous_output != self.outpoint {
            return Err("transaction spends a different LayerTree coin");
        }
        if prevout.value.to_sat() != current.root().sum
            || prevout.script_pubkey != tree_spk(current.root().hash, self.script_root)?
        {
            return Err("previous coin disagrees with canonical LayerTree root");
        }
        let output = transaction
            .output
            .first()
            .ok_or("transaction has no LayerTree successor output")?;
        if output.value.to_sat() != next.root().sum {
            return Err("successor principal differs from Merkle-sum root");
        }
        if next.root().sum == 0 {
            if output.script_pubkey != ScriptBuf::from_bytes(vec![0x6a]) {
                return Err("terminal LayerTree output must be zero-value OP_RETURN");
            }
        } else if output.script_pubkey != tree_spk(next.root().hash, self.script_root)? {
            return Err("successor output commits to a different LayerTree root");
        }
        let txid = transaction.compute_txid();
        self.pending = Some(SigningReservation {
            input: self.outpoint,
            txid,
            before: current.root(),
            after: next.root(),
        });
        Ok(txid)
    }

    /// Check that a signer is using the *exact* durably reserved transaction.
    ///
    /// This is a prerequisite, not a signing API: the application must also
    /// check that the journal was successfully synced under an exclusive lock.
    pub fn permit(&self, transaction: &Transaction) -> Result<Txid, &'static str> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("no pending LayerTree signing reservation")?;
        if transaction.compute_txid() != pending.txid
            || transaction
                .input
                .first()
                .map(|input| input.previous_output)
                != Some(pending.input)
        {
            return Err("signing transaction differs from reserved LayerTree intent");
        }
        Ok(pending.txid)
    }

    /// Acknowledge an independently verified *confirmed* winning spend.
    ///
    /// This method checks the pending intent's exact txid and successor root.
    /// The caller is responsible for proof of confirmation and chain ancestry.
    /// An unrelated winning transaction cannot be silently made canonical.
    pub fn confirm(
        &mut self,
        txid: Txid,
        current: &Tree,
        next: &Tree,
    ) -> Result<(), &'static str> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("no LayerTree reservation to confirm")?;
        if pending.txid != txid || pending.input != self.outpoint {
            return Err("confirmed spend differs from reserved transaction");
        }
        if pending.before != current.root() || pending.after != next.root() {
            return Err("confirmed successor differs from reserved allocation");
        }
        self.guard.advance(self.guard.tree_id(), current, next)?;
        self.outpoint = OutPoint::new(txid, 0);
        self.pending = None;
        Ok(())
    }
}

fn staging_path(path: &Path) -> PathBuf {
    let id = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".stage-{}-{id}", std::process::id()));
    PathBuf::from(value)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

/// Atomically replace a previously known journal using a synced temporary file.
///
/// The caller must own the per-path exclusive file lock for the whole signing
/// operation. Local file atomics do not authenticate a malicious disk snapshot.
fn persist(path: &Path, state: &LineageJournal) -> io::Result<()> {
    let encoded = serde_json::to_vec(state)?;
    let stage = staging_path(path);
    let result = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut out = opts.open(&stage)?;
        out.write_all(&encoded)?;
        out.sync_all()?;
        fs::rename(&stage, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

/// Exclusive single-process signing coordinator with synchronized state.
///
/// The OS lock remains held until this handle is dropped. Concurrent local
/// processes using this API serialize their journal mutations and signing
/// attempts. A distributed signer must provide an equivalent fencing protocol.
pub struct LockedLineage {
    path: PathBuf,
    _lock: File,
    state: LineageJournal,
    poisoned: bool,
}

impl LockedLineage {
    fn acquire(path: &Path) -> io::Result<File> {
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(lock_path(path))?;
        file.lock()?;
        Ok(file)
    }

    /// Create the first durable record; refuse to overwrite an existing one.
    ///
    /// The parent directory must already exist. A trusted application must
    /// keep this journal alongside its signer wallet and independently
    /// authenticate the funded chain outpoint.
    pub fn create(path: impl AsRef<Path>, state: LineageJournal) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = Self::acquire(&path)?;
        if path.exists() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "existing LayerTree journal must be reopened",
            ));
        }
        persist(&path, &state)?;
        Ok(Self {
            path,
            _lock: lock,
            state,
            poisoned: false,
        })
    }

    /// Restore an existing journal and acquire its exclusive signing lock.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = Self::acquire(&path)?;
        let state: LineageJournal = serde_json::from_slice(&fs::read(&path)?)?;
        if state.version != JOURNAL_VERSION {
            return Err(invalid("unsupported LayerTree journal version"));
        }
        Ok(Self {
            path,
            _lock: lock,
            state,
            poisoned: false,
        })
    }

    /// Inspect the current durable state while this instance holds the lock.
    pub fn state(&self) -> &LineageJournal {
        &self.state
    }

    /// Atomically reserve an unsigned transaction before returning permission
    /// for the caller to obtain any owner, operator or oracle signature.
    pub fn reserve(
        &mut self,
        current: &Tree,
        next: &Tree,
        prevout: &TxOut,
        transaction: &Transaction,
    ) -> io::Result<Txid> {
        if self.poisoned {
            return Err(invalid("uncertain LayerTree journal write; reopen after recovery"));
        }
        let mut proposed = self.state.clone();
        let txid = proposed
            .reserve(current, next, prevout, transaction)
            .map_err(invalid)?;
        if let Err(error) = persist(&self.path, &proposed) {
            self.poisoned = true;
            return Err(error);
        }
        self.state = proposed;
        Ok(txid)
    }

    /// Verify the exact unsigned transaction following the successful sync.
    pub fn permit(&self, transaction: &Transaction) -> io::Result<Txid> {
        if self.poisoned {
            return Err(invalid("uncertain LayerTree journal write; reopen after recovery"));
        }
        self.state.permit(transaction).map_err(invalid)
    }

    /// Persist the canonical root after the chain independently confirms the
    /// reserved exact transaction. The user must authenticate that confirmation.
    pub fn confirm(&mut self, txid: Txid, current: &Tree, next: &Tree) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid("uncertain LayerTree journal write; reopen after recovery"));
        }
        let mut proposed = self.state.clone();
        proposed.confirm(txid, current, next).map_err(invalid)?;
        if let Err(error) = persist(&self.path, &proposed) {
            self.poisoned = true;
            return Err(error);
        }
        self.state = proposed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tree::NUMS;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::XOnlyPublicKey;
    use bitcoin::{Amount, Sequence, TxIn};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_NUMBER: AtomicU64 = AtomicU64::new(0);

    fn member(nonce: u32, amount: u64) -> super::super::tree::Leaf {
        let key = XOnlyPublicKey::from_slice(&NUMS).unwrap();
        super::super::tree::Leaf {
            amount,
            exit_key: key,
            owner_key: key,
            evictor_key: key,
            evict_after: 200,
            nonce,
            seq: 0,
        }
    }

    fn setup() -> (LineageJournal, Tree, TxOut) {
        let mut tree = Tree::new(2).unwrap();
        tree.set(0, Some(member(1, 60_000))).unwrap();
        tree.set(1, Some(member(2, 40_000))).unwrap();
        let anchor = OutPoint::new(
            bitcoin::Txid::from_byte_array(sha256::Hash::hash(b"journal-genesis").to_byte_array()),
            0,
        );
        let journal = LineageJournal::bootstrap([7; 32], [8; 32], anchor, &tree).unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: tree_spk(tree.root().hash, [8; 32]).unwrap(),
        };
        (journal, tree, prevout)
    }

    fn transaction(journal: &LineageJournal, after: &Tree) -> Transaction {
        let script_pubkey = if after.root().sum == 0 {
            ScriptBuf::from_bytes(vec![0x6a])
        } else {
            tree_spk(after.root().hash, [8; 32]).unwrap()
        };
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: journal.outpoint(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(after.root().sum),
                script_pubkey,
            }],
        }
    }

    #[test]
    fn transaction_is_pinned_to_parent_and_exact_successor() {
        let (mut journal, tree, prevout) = setup();
        let mut after = tree.clone();
        after.set(0, None).unwrap();
        let mut bad = transaction(&journal, &after);
        bad.output[0].value += Amount::ONE_SAT;
        assert!(journal.reserve(&tree, &after, &prevout, &bad).is_err());
        assert!(journal.pending().is_none());
        let tx = transaction(&journal, &after);
        let txid = journal.reserve(&tree, &after, &prevout, &tx).unwrap();
        let mut redirect = tx.clone();
        redirect.output[0].value -= Amount::ONE_SAT;
        assert!(journal.permit(&redirect).is_err());
        assert_eq!(journal.permit(&tx).unwrap(), txid);
        assert!(journal.reserve(&tree, &after, &prevout, &tx).is_err());
        assert!(journal.confirm(redirect.compute_txid(), &tree, &after).is_err());
        assert!(journal.pending().is_some());
        journal.confirm(txid, &tree, &after).unwrap();
        assert_eq!(journal.root().sum, 40_000);
        assert_eq!(journal.outpoint(), OutPoint::new(txid, 0));
    }

    #[test]
    fn abandoned_signing_reservation_stays_blocked_after_restart() {
        let (journal, tree, prevout) = setup();
        let path = std::env::temp_dir().join(format!(
            "sapio-lineage-journal-{}-{}.json",
            std::process::id(),
            TEMP_NUMBER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut after = tree.clone();
        after.set(0, None).unwrap();
        let tx = transaction(&journal, &after);
        {
            let mut on_disk = LockedLineage::create(&path, journal).unwrap();
            let txid = on_disk.reserve(&tree, &after, &prevout, &tx).unwrap();
            assert_eq!(on_disk.permit(&tx).unwrap(), txid);
        }
        {
            let mut recovered = LockedLineage::open(&path).unwrap();
            assert_eq!(recovered.permit(&tx).unwrap(), tx.compute_txid());
            assert!(recovered.reserve(&tree, &after, &prevout, &tx).is_err());
            assert!(recovered
                .confirm(bitcoin::Txid::from_byte_array([9; 32]), &tree, &after)
                .is_err());
            recovered.confirm(tx.compute_txid(), &tree, &after).unwrap();
        }
        {
            let recovered = LockedLineage::open(&path).unwrap();
            assert_eq!(recovered.state().root().sum, 40_000);
            assert!(recovered.state().pending().is_none());
            assert_eq!(recovered.state().guard().historical_identities(), 2);
        }
        assert!(LockedLineage::create(&path, setup().0).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_file(lock_path(&path)).unwrap();
    }

    #[test]
    fn historical_identity_tombstones_survive_confirmed_and_reloaded_state() {
        let (mut journal, tree, prevout) = setup();
        let mut exited = tree.clone();
        exited.set(0, None).unwrap();
        let tx = transaction(&journal, &exited);
        journal.reserve(&tree, &exited, &prevout, &tx).unwrap();
        journal.confirm(tx.compute_txid(), &tree, &exited).unwrap();
        let mut replay = exited.clone();
        replay.set(0, tree.leaf(0).cloned()).unwrap();
        let synthetic = transaction(&journal, &replay);
        let new_prevout = TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: tree_spk(exited.root().hash, [8; 32]).unwrap(),
        };
        assert!(journal.reserve(&exited, &replay, &new_prevout, &synthetic).is_err());
    }

    #[test]
    fn invalid_predecessor_or_script_cannot_consume_a_reservation() {
        let (mut journal, tree, prevout) = setup();
        let mut after = tree.clone();
        after.set(0, None).unwrap();
        let mut tx = transaction(&journal, &after);
        tx.input[0].previous_output = OutPoint::new(
            bitcoin::Txid::from_byte_array([5; 32]),
            0,
        );
        assert!(journal.reserve(&tree, &after, &prevout, &tx).is_err());
        let mut wrong_prevout = prevout.clone();
        wrong_prevout.script_pubkey = ScriptBuf::new();
        let tx = transaction(&journal, &after);
        assert!(journal.reserve(&tree, &after, &wrong_prevout, &tx).is_err());
        assert!(journal.pending().is_none());
    }

    #[test]
    fn terminal_pool_cannot_be_reopened_using_the_old_record() {
        let (mut journal, tree, prevout) = setup();
        let empty = Tree::new(2).unwrap();
        let tx = transaction(&journal, &empty);
        journal.reserve(&tree, &empty, &prevout, &tx).unwrap();
        journal.confirm(tx.compute_txid(), &tree, &empty).unwrap();
        let new_prevout = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        };
        let attempt = transaction(&journal, &tree);
        assert!(journal.reserve(&empty, &tree, &new_prevout, &attempt).is_err());
    }
}
