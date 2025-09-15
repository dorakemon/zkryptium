// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    ciphersuites::BbsCiphersuite,
    generators::Generators,
    keys::{BBSplusPublicKey, BBSplusSecretKey},
};
use crate::{
    errors::Error,
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::bbsplus_utils::{get_random, hash_to_scalar, ScalarExt},
    },
};
use alloc::{string::String, vec::Vec};
use bls12_381_plus::{multi_miller_loop, G1Projective, G2Prepared, G2Projective, Scalar};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
use rand_core::RngCore;

#[derive(Clone, Debug)]
pub struct CommitmentProof {
    pub commitment_proof: G1Projective,
    pub challenge: Scalar,
    pub s_response: Vec<Scalar>,
}

#[derive(Clone, Debug)]
pub struct CommitmentWithProof {
    pub commitment: G1Projective,
    pub proof: CommitmentProof,
}

#[derive(Clone, Debug)]
pub struct DeviceSession {
    pub issue_id: String,
    pub r: Scalar,
}

#[derive(Clone, Debug)]
pub struct BBSplusDeviceSignature {
    pub A: G1Projective,
    pub e: Scalar,
}

/// CommitUsk algorithm from VC issuance phase
///
/// Mathematical formula:
/// - r ← $Z_p, issueId ← {0,1}*
/// - com = h_0^usk · h_c^r
/// - π_com = SPK{(usk, r): com = h_0^usk · h_c^r}(nonce_I)
///
/// Returns: (issueId, commitment_with_proof, r)
pub fn commit_usk<CS, R>(
    rng: &mut R,
    prm: &Generators,
    usk: &Scalar,
    nonce_i: &[u8],
) -> Result<(String, CommitmentWithProof, Scalar), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    R: RngCore,
{
    let r = get_random(rng);
    let issue_id = hex::encode(get_random(rng).to_bytes_be());

    let h_c = prm.values.get(0).ok_or(Error::NotEnoughGenerators)?;
    let h_0 = prm.values.get(1).ok_or(Error::NotEnoughGenerators)?;

    // com = h_0^usk · h_c^r
    let commitment = h_0 * usk + h_c * r;

    // Generate SPK proof
    let usk_tilde = get_random(rng);
    let r_tilde = get_random(rng);

    // com_tilde = h_0^{usk_tilde} · h_c^{r_tilde}
    let commitment_tilde = h_0 * usk_tilde + h_c * r_tilde;

    // Calculate challenge for SPK: H(com || com_tilde || nonce_I)
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&commitment.to_affine().to_compressed());
    challenge_input.extend_from_slice(&commitment_tilde.to_affine().to_compressed());
    challenge_input.extend_from_slice(nonce_i);

    let challenge = hash_to_scalar::<CS>(&challenge_input, b"SPK_challenge")?;

    // Response values: s_usk = usk_tilde + usk · challenge
    let s_usk = usk_tilde + usk * challenge;
    // s_r = r_tilde + r · challenge
    let s_r = r_tilde + r * challenge;

    let proof = CommitmentProof {
        commitment_proof: commitment_tilde,
        challenge,
        s_response: vec![s_usk, s_r],
    };

    Ok((issue_id, CommitmentWithProof { commitment, proof }, r))
}

/// VerifyCommitUsk algorithm from VC issuance phase
///
/// Verifies the zero-knowledge proof that the commitment is correctly formed
/// π_com verification
///
/// Returns: Ok(()) if valid, Error otherwise
pub fn verify_commit_usk<CS>(
    prm: &Generators,
    commitment_with_proof: &CommitmentWithProof,
    nonce_i: &[u8],
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let h_c = prm.values.get(0).ok_or(Error::NotEnoughGenerators)?;
    let h_0 = prm.values.get(1).ok_or(Error::NotEnoughGenerators)?;

    let s_usk = commitment_with_proof
        .proof
        .s_response
        .get(0)
        .ok_or(Error::InvalidCommitmentProof)?;
    let s_r = commitment_with_proof
        .proof
        .s_response
        .get(1)
        .ok_or(Error::InvalidCommitmentProof)?;

    // Verify: com_tilde ?= h_0^{s_usk} · h_c^{s_r} · com^{-challenge}
    let commitment_verify = h_0 * s_usk + h_c * s_r
        - commitment_with_proof.commitment * commitment_with_proof.proof.challenge;

    if commitment_verify != commitment_with_proof.proof.commitment_proof {
        return Err(Error::InvalidCommitmentProof);
    }

    let mut challenge_input = Vec::new();
    challenge_input
        .extend_from_slice(&commitment_with_proof.commitment.to_affine().to_compressed());
    challenge_input.extend_from_slice(
        &commitment_with_proof
            .proof
            .commitment_proof
            .to_affine()
            .to_compressed(),
    );
    challenge_input.extend_from_slice(nonce_i);

    let challenge_verify = hash_to_scalar::<CS>(&challenge_input, b"SPK_challenge")?;

    if challenge_verify != commitment_with_proof.proof.challenge {
        return Err(Error::InvalidCommitmentProof);
    }

    Ok(())
}

/// BlindSign algorithm from VC issuance phase
///
/// Mathematical formula:
/// - e ← $Z_p
/// - A = (g_1 · com · ∏_{i∈L} h_i^{m_i})^{1/(sk+e)}
///
/// Where com contains the committed usk and r values
/// Returns: BBSplusDeviceSignature (A, e)
pub fn blind_sign<CS, R>(
    rng: &mut R,
    prm: &Generators,
    sk: &BBSplusSecretKey,
    messages: &[BBSplusMessage],
    commitment: &G1Projective,
) -> Result<BBSplusDeviceSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    R: RngCore,
{
    let e = get_random(rng);

    // B = g_1 · com · ∏_{i∈L} h_i^{m_i}
    let mut b = prm.g1_base_point + commitment;

    let h_points = &prm.values[2..];
    if h_points.len() < messages.len() {
        return Err(Error::NotEnoughGenerators);
    }

    for (i, msg) in messages.iter().enumerate() {
        b = b + h_points[i] * msg.value;
    }

    let sk_e = sk.0 + e;
    let sk_e_inv = Option::<Scalar>::from(sk_e.invert()).ok_or(Error::InvalidSignature)?;

    // A = B^{1/(sk+e)}
    let a = b * sk_e_inv;

    Ok(BBSplusDeviceSignature { A: a, e })
}

/// Verify algorithm from VC issuance phase
///
/// Mathematical formula:
/// e(A, pk · g_2^e) = e(g_1 · com · ∏_{i∈L} h_i^{m_i}, g_2)
///
/// Verifies the BBS signature is valid for the commitment and messages
/// Returns: Ok(()) if valid, Error otherwise
pub fn verify<CS>(
    prm: &Generators,
    pk: &BBSplusPublicKey,
    signature: &BBSplusDeviceSignature,
    commitment: &G1Projective,
    messages: &[BBSplusMessage],
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    // B = g_1 · com · ∏_{i∈L} h_i^{m_i}
    let mut b = prm.g1_base_point + commitment;

    let h_points = &prm.values[2..];
    if h_points.len() < messages.len() {
        return Err(Error::NotEnoughGenerators);
    }

    for (i, msg) in messages.iter().enumerate() {
        b = b + h_points[i] * msg.value;
    }

    let g2 = G2Projective::GENERATOR;
    let pk_e_g2 = pk.0 + g2 * signature.e;

    let pairing1 = multi_miller_loop(&[(
        &signature.A.to_affine(),
        &G2Prepared::from(pk_e_g2.to_affine()),
    )])
    .final_exponentiation();

    let pairing2 = multi_miller_loop(&[(&b.to_affine(), &G2Prepared::from(g2.to_affine()))])
        .final_exponentiation();

    if pairing1 != pairing2 {
        return Err(Error::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbsplus::{ciphersuites::Bls12381Sha256, keys::BBSplusSecretKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_vc_issuance_flow() {
        let mut rng = StdRng::from_seed([1u8; 32]);

        // Setup
        let sk = BBSplusSecretKey(get_random(&mut rng));
        let pk = sk.public_key();

        // Create generators for usk, r, and 3 messages
        let prm = Generators::create::<Bls12381Sha256>(5, Some(Bls12381Sha256::API_ID));

        // Device secret key
        let usk = get_random(&mut rng);
        let nonce_i = b"test_nonce";

        // Step 1: CommitUsk
        let (issue_id, commitment_with_proof, _r) =
            commit_usk::<Bls12381Sha256, _>(&mut rng, &prm, &usk, nonce_i).unwrap();

        assert!(!issue_id.is_empty());
        assert!(commitment_with_proof.commitment != G1Projective::IDENTITY);

        // Step 2: VerifyCommitUsk
        verify_commit_usk::<Bls12381Sha256>(&prm, &commitment_with_proof, nonce_i).unwrap();

        // Step 3: BlindSign
        let messages = vec![
            BBSplusMessage::new(Scalar::from(123u64)),
            BBSplusMessage::new(Scalar::from(456u64)),
            BBSplusMessage::new(Scalar::from(789u64)),
        ];

        let signature = blind_sign::<Bls12381Sha256, _>(
            &mut rng,
            &prm,
            &sk,
            &messages,
            &commitment_with_proof.commitment,
        )
        .unwrap();

        assert!(signature.A != G1Projective::IDENTITY);

        // Step 4: Verify
        let result = verify::<Bls12381Sha256>(
            &prm,
            &pk,
            &signature,
            &commitment_with_proof.commitment,
            &messages,
        );

        assert!(result.is_ok(), "Verification should succeed");
    }
}
