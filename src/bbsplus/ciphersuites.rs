// SPDX-FileCopyrightText: 2023 Fondazione LINKS
//
// SPDX-License-Identifier: APACHE-2.0

use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha2::Sha256;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXof, ExpandMsgXmd};

use crate::schemes::algorithms::Ciphersuite;


pub trait BbsCiphersuite: Eq + 'static + Ciphersuite{
    const ID: &'static [u8];
    const GENERATOR_SEED: &'static [u8];
    const GENERATOR_SEED_BP: &'static [u8];
    const GENERATOR_SEED_DST: &'static [u8];
    const GENERATOR_DST: &'static [u8];
    const GENERATOR_SIG_DST: &'static [u8];
    type Expander: ExpandMsg<'static>;
    const EXPAND_LEN: usize = 48;
    const OCTECT_SCALAR_LEN: usize = 32;
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Shake256{}
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Sha256 {}


impl BbsCiphersuite for Bls12381Shake256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    const GENERATOR_SEED: &'static [u8] =  b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_BP: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_DST_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_DET_DST_";
    type Expander= ExpandMsgXof<Shake256>;

}


impl BbsCiphersuite for Bls12381Sha256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const GENERATOR_SEED: &'static [u8] =  b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_BP: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_DST_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_DET_DST_";
    type Expander= ExpandMsgXmd<Sha256>;
}

