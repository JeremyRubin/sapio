// Copyright Judica, Inc 2022
//
// This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bitcoin::consensus::serialize;
use bitcoin::schnorr::TapTweak;
use bitcoin::secp256k1::rand::Rng;
use bitcoin::secp256k1::{rand, Signing, Verification};
use bitcoin::util::bip32::{ExtendedPubKey, KeySource};
use bitcoin::util::sighash::Prevouts;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::util::taproot::TapSighashHash;
use bitcoin::XOnlyPublicKey;
use bitcoin::{
    psbt::PartiallySignedTransaction, secp256k1::Secp256k1, util::bip32::ExtendedPrivKey,
};
use bitcoin::{KeyPair, TxOut};
use bitcoin::{Network, SchnorrSig};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;

pub mod external_api;

pub struct SigningKey(pub ExtendedPrivKey);

impl SigningKey {
    pub async fn read_key_from_file(file_name: &std::ffi::OsStr) -> Result<Self, Box<dyn Error>> {
        let buf = tokio::fs::read(file_name).await?;
        Ok(SigningKey(ExtendedPrivKey::decode(&buf)?))
    }
    pub async fn show_pubkey(input: &std::ffi::OsStr) -> Result<(), Box<dyn Error>> {
        let xpriv = Self::read_key_from_file(input).await?.0;
        println!("{}", ExtendedPubKey::from_priv(&Secp256k1::new(), &xpriv));
        Ok(())
    }

    pub fn new_key(network: &str, out: &std::ffi::OsStr) -> Result<(), Box<dyn Error>> {
        let entropy: [u8; 32] = rand::thread_rng().gen();
        let xpriv = ExtendedPrivKey::new_master(Network::from_str(network)?, &entropy)?;
        std::fs::write(out, &xpriv.encode())?;
        println!("{}", ExtendedPubKey::from_priv(&Secp256k1::new(), &xpriv));
        Ok(())
    }
    pub fn sign(
        &self,
        mut psbt: PartiallySignedTransaction,
        hash_ty: bitcoin::SchnorrSighashType,
    ) -> Result<Vec<u8>, PSBTSigningError> {
        self.sign_psbt_mut(&mut psbt, &Secp256k1::new(), hash_ty)?;
        let bytes = serialize(&psbt);
        Ok(bytes)
    }
    pub fn sign_psbt<C: Signing + Verification>(
        &self,
        psbt: PartiallySignedTransaction,
        secp: &Secp256k1<C>,
        hash_ty: bitcoin::SchnorrSighashType,
    ) -> Result<PartiallySignedTransaction, (PartiallySignedTransaction, PSBTSigningError)> {
        self.sign_psbt_input(psbt, secp, 0, hash_ty)
    }
    pub fn sign_psbt_mut<C: Signing + Verification>(
        &self,
        psbt: &mut PartiallySignedTransaction,
        secp: &Secp256k1<C>,
        hash_ty: bitcoin::SchnorrSighashType,
    ) -> Result<(), PSBTSigningError> {
        self.sign_psbt_input_mut(psbt, secp, 0, hash_ty)
    }
    pub fn sign_psbt_input<C: Signing + Verification>(
        &self,
        mut psbt: PartiallySignedTransaction,
        secp: &Secp256k1<C>,
        idx: usize,
        hash_ty: bitcoin::SchnorrSighashType,
    ) -> Result<PartiallySignedTransaction, (PartiallySignedTransaction, PSBTSigningError)> {
        match self.sign_psbt_input_mut(&mut psbt, secp, idx, hash_ty) {
            Ok(()) => Ok(psbt),
            Err(e) => Err((psbt, e)),
        }
    }
    pub fn sign_psbt_input_mut<C: Signing + Verification>(
        &self,
        psbt: &mut PartiallySignedTransaction,
        secp: &Secp256k1<C>,
        idx: usize,
        hash_ty: bitcoin::SchnorrSighashType,
    ) -> Result<(), PSBTSigningError> {
        let tx = psbt.clone().extract_tx();
        let utxos: Vec<TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(i, o)| {
                if let Some(ref utxo) = o.witness_utxo {
                    Ok(utxo.clone())
                } else {
                    Err(i)
                }
            })
            .collect::<Result<Vec<TxOut>, usize>>()
            .map_err(|u| PSBTSigningError::NoUTXOAtIndex(u))?;
        let mut sighash = bitcoin::util::sighash::SighashCache::new(&tx);
        let input = &mut psbt
            .inputs
            .get_mut(idx)
            .ok_or(PSBTSigningError::NoInputAtIndex(idx))?;
        let prevouts = &Prevouts::All(&utxos);
        self.sign_taproot_top_key(secp, input, &mut sighash, prevouts, hash_ty);
        self.sign_all_tapleaf_branches(secp, input, &mut sighash, prevouts, hash_ty);
        Ok(())
    }

    fn sign_all_tapleaf_branches<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        input: &mut bitcoin::psbt::Input,
        sighash: &mut bitcoin::util::sighash::SighashCache<&bitcoin::Transaction>,
        prevouts: &Prevouts<TxOut>,
        hash_ty: bitcoin::SchnorrSighashType,
    ) {
        let signers = self.compute_matching_keys(secp, &input.tap_key_origins);
        for (kp, vtlh) in signers {
            for tlh in vtlh {
                let sig = get_sig(
                    sighash,
                    prevouts,
                    hash_ty,
                    secp,
                    &kp,
                    &Some((*tlh, DEFAULT_CODESEP)),
                );
                input
                    .tap_script_sigs
                    .insert((kp.x_only_public_key().0, *tlh), sig);
            }
        }
    }

    fn sign_taproot_top_key<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        input: &mut bitcoin::psbt::Input,
        sighash: &mut bitcoin::util::sighash::SighashCache<&bitcoin::Transaction>,
        prevouts: &Prevouts<TxOut>,
        hash_ty: bitcoin::SchnorrSighashType,
    ) {
        let untweaked = self.0.to_keypair(secp);
        let pk = XOnlyPublicKey::from_keypair(&untweaked);
        let tweaked = untweaked
            .tap_tweak(secp, input.tap_merkle_root)
            .into_inner();
        let _tweaked_pk = tweaked.public_key();
        if input.tap_internal_key == Some(pk.0) {
            let sig = get_sig(sighash, prevouts, hash_ty, secp, &tweaked, &None);
            input.tap_key_sig = Some(sig);
        }
    }

    /// Compute keypairs for all matching fingerprints
    fn compute_matching_keys<'a, C: Signing>(
        &'a self,
        secp: &'a Secp256k1<C>,
        input: &'a BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    ) -> impl Iterator<Item = (KeyPair, &'a Vec<TapLeafHash>)> + 'a {
        let fingerprint = self.0.fingerprint(secp);
        input
            .iter()
            .filter(move |(_, (_, (f, _)))| *f == fingerprint)
            .filter_map(|(x, (vlth, (_, path)))| {
                let new_priv = self.0.derive_priv(secp, path).ok()?.to_keypair(secp);
                if new_priv.public_key().x_only_public_key().0 == *x {
                    Some((new_priv, vlth))
                } else {
                    None
                }
            })
    }
}

#[derive(Debug, Clone)]
pub enum PSBTSigningError {
    NoUTXOAtIndex(usize),
    NoInputAtIndex(usize),
}

impl Display for PSBTSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for PSBTSigningError {}

const DEFAULT_CODESEP: u32 = 0xffff_ffff;
fn get_sig<C: Signing>(
    sighash: &mut bitcoin::util::sighash::SighashCache<&bitcoin::Transaction>,
    prevouts: &Prevouts<TxOut>,
    hash_ty: bitcoin::SchnorrSighashType,
    secp: &Secp256k1<C>,
    kp: &bitcoin::KeyPair,
    path: &Option<(TapLeafHash, u32)>,
) -> SchnorrSig {
    let annex = None;
    let sighash: TapSighashHash = sighash
        .taproot_signature_hash(0, prevouts, annex, *path, hash_ty)
        .expect("Signature hash cannot fail...");
    let msg = bitcoin::secp256k1::Message::from_slice(&sighash[..]).expect("Size must be correct.");
    let sig = secp.sign_schnorr_no_aux_rand(&msg, kp);
    SchnorrSig { sig, hash_ty }
}
