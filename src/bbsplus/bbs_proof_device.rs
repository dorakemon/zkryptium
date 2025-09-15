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
    bbs_device::BBSplusDeviceSignature, ciphersuites::BbsCiphersuite, generators::Generators,
    keys::BBSplusPublicKey,
};
use crate::{
    errors::Error,
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::bbsplus_utils::{get_random, hash_to_scalar, ScalarExt},
    },
};
use alloc::vec::Vec;
use bls12_381_plus::{multi_miller_loop, G1Projective, G2Prepared, G2Projective, Scalar};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
use rand_core::RngCore;

#[derive(Clone, Debug)]
pub struct CommitForProofOutput {
    pub usk_tilde: Scalar,
    pub r_tilde: Scalar,
    pub challenge_d: Scalar,
    pub h0_usk_tilde: G1Projective, // h_0^ũsk
    pub hc_r_tilde: G1Projective,   // h_c^r̃
}

#[derive(Clone, Debug)]
pub struct ProofPreComputation {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub e_tilde: Scalar,
    pub r1_tilde: Scalar,
    pub r3_tilde: Scalar,
    pub m_tilde: Vec<Scalar>,
    pub e: Scalar,
    pub r1: Scalar,
    pub r3: Scalar,
    pub m_hidden: Vec<Scalar>,
}

#[derive(Clone, Debug)]
pub struct DeviceProof {
    pub a_bar: G1Projective,
    pub b_bar: G1Projective,
    pub d: G1Projective,
    pub e_hat: Scalar,
    pub r1_hat: Scalar,
    pub r3_hat: Scalar,
    pub m_hat: Vec<Scalar>,
    pub usk_hat: Scalar,
    pub r_hat: Scalar,
    pub challenge: Scalar,
    pub challenge_d: Scalar,
}

/// CommitForProof algorithm from VP presentation phase
///
/// Mathematical formula:
/// - ũsk, r̃, challenge_D ← $Z_p
/// - return (ũsk, r̃, challenge_D, h_0^ũsk, h_c^r̃)
///
/// Device generates random values for proof generation
/// Returns: CommitForProofOutput with all random values
pub fn commit_for_proof<CS, R>(rng: &mut R, prm: &Generators) -> Result<CommitForProofOutput, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    R: RngCore,
{
    let usk_tilde = get_random(rng);
    let r_tilde = get_random(rng);
    let challenge_d = get_random(rng);

    // Use consistent generator assignment with VC phase
    // h_0 is for usk, h_c is for r (as in com = h_0^usk · h_c^r)
    let h_c = prm.values.get(0).ok_or(Error::NotEnoughGenerators)?;
    let h_0 = prm.values.get(1).ok_or(Error::NotEnoughGenerators)?;

    // Consistent with VC phase: h_0^ũsk and h_c^r̃
    let h0_usk_tilde = h_0 * usk_tilde; // h_0^ũsk
    let hc_r_tilde = h_c * r_tilde; // h_c^r̃

    Ok(CommitForProofOutput {
        usk_tilde,
        r_tilde,
        challenge_d,
        h0_usk_tilde, // h_0^ũsk
        hc_r_tilde,   // h_c^r̃
    })
}

/// ProofGen1 algorithm from VP presentation phase
///
/// Mathematical formulas:
/// - B = g_1 · com · ∏_{i∈L} h_i^{m_i}
/// - r1, r2 ← $Z_p, r3 = 1/r2
/// - D = B^{r2}, Ā = A^{r1·r2}, B̄ = Ā^{-e} · D^{r1}
/// - ẽ, r̃1, r̃3, {m̃_i}_{i∈U} ← $Z_p
/// - T1 = Ā^{ẽ} · D^{r̃1}
/// - T2 = D^{r̃3} · h_0^ũsk · h_c^r̃ · ∏_{i∈U} h_i^{m̃_i}
/// - challenge_C = Hash(Ā || B̄ || D || T1 || T2 || |𝒟| || 𝒟 || {m_i}_{i∈𝒟} || nonce_V)
///
/// Returns: (ProofPreComputation, challenge_C)
pub fn proof_gen1<CS, R>(
    rng: &mut R,
    prm: &Generators,
    _pk: &BBSplusPublicKey,
    signature: &BBSplusDeviceSignature,
    commitment: &G1Projective,
    messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    nonce_v: &[u8],
    commit_output: &CommitForProofOutput,
) -> Result<(ProofPreComputation, Scalar), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    R: RngCore,
{
    // Calculate B = g_1 · com · ∏_{i∈L} h_i^{m_i}
    let mut b = prm.g1_base_point + commitment;
    let h_points = &prm.values[2..];

    if h_points.len() < messages.len() {
        return Err(Error::NotEnoughGenerators);
    }

    for (i, msg) in messages.iter().enumerate() {
        b = b + h_points[i] * msg.value;
    }

    // Random values
    let r1 = get_random(rng);
    let r2 = get_random(rng);
    let r3 = Option::<Scalar>::from(r2.invert()).ok_or(Error::InvalidProofOfKnowledgeSignature)?;

    // Calculate D = B^{r2}, Ā = A^{r1·r2}, B̄ = Ā^{-e} · D^{r1}
    let d = b * r2;
    let a_bar = signature.A * (r1 * r2);
    let b_bar = a_bar * (-signature.e) + d * r1;

    // Generate random tildes
    let e_tilde = get_random(rng);
    let r1_tilde = get_random(rng);
    let r3_tilde = get_random(rng);

    // Undisclosed message tildes
    let mut m_tilde = Vec::new();
    let mut m_hidden = Vec::new();
    for (i, msg) in messages.iter().enumerate() {
        if !disclosed_indexes.contains(&i) {
            m_tilde.push(get_random(rng));
            m_hidden.push(msg.value);
        }
    }

    // Calculate T1 = Ā^{ẽ} · D^{r̃1}
    let t1 = a_bar * e_tilde + d * r1_tilde;

    // Calculate T2 = D^{r̃3} · h_0^ũsk · h_c^r̃ · ∏_{i∈U} h_i^{m̃_i}
    // Using consistent generators: h_0 for usk, h_c for r
    let mut t2 = d * r3_tilde + commit_output.h0_usk_tilde + commit_output.hc_r_tilde;
    let mut undisclosed_idx = 0;
    for (i, _) in messages.iter().enumerate() {
        if !disclosed_indexes.contains(&i) {
            t2 = t2 + h_points[i] * m_tilde[undisclosed_idx];
            undisclosed_idx += 1;
        }
    }

    // Calculate challenge_c
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&a_bar.to_affine().to_compressed());
    challenge_input.extend_from_slice(&b_bar.to_affine().to_compressed());
    challenge_input.extend_from_slice(&d.to_affine().to_compressed());
    challenge_input.extend_from_slice(&t1.to_affine().to_compressed());
    challenge_input.extend_from_slice(&t2.to_affine().to_compressed());
    challenge_input.extend_from_slice(&(disclosed_indexes.len() as u64).to_le_bytes());

    for idx in disclosed_indexes {
        challenge_input.extend_from_slice(&(*idx as u64).to_le_bytes());
    }

    for idx in disclosed_indexes {
        if let Some(msg) = messages.get(*idx) {
            challenge_input.extend_from_slice(&msg.value.to_bytes_be());
        }
    }

    challenge_input.extend_from_slice(nonce_v);

    let challenge_c = hash_to_scalar::<CS>(&challenge_input, b"challenge")?;

    Ok((
        ProofPreComputation {
            a_bar,
            b_bar,
            d,
            e_tilde,
            r1_tilde,
            r3_tilde,
            m_tilde,
            e: signature.e,
            r1,
            r3,
            m_hidden,
        },
        challenge_c,
    ))
}

/// RespondForProof algorithm from VP presentation phase
///
/// Mathematical formulas:
/// - challenge = Hash(challenge_D || challenge_C)
/// - ûsk = ũsk + usk · challenge
/// - r̂ = r̃ + r · challenge
///
/// Device computes response values using stored secrets
/// Returns: (ûsk, r̂)
pub fn respond_for_proof<CS>(
    _prm: &Generators,
    usk: &Scalar,
    r: &Scalar,
    commit_output: &CommitForProofOutput,
    challenge_c: &Scalar,
) -> Result<(Scalar, Scalar), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    // Calculate combined challenge = Hash(challenge_D || challenge_C)
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&commit_output.challenge_d.to_bytes_be());
    challenge_input.extend_from_slice(&challenge_c.to_bytes_be());

    let challenge = hash_to_scalar::<CS>(&challenge_input, b"combined_challenge")?;

    // Calculate response values: ûsk = ũsk + usk · challenge, r̂ = r̃ + r · challenge
    let usk_hat = commit_output.usk_tilde + usk * challenge;
    let r_hat = commit_output.r_tilde + r * challenge;

    Ok((usk_hat, r_hat))
}

/// ProofGen2 algorithm from VP presentation phase
///
/// Mathematical formulas:
/// - challenge = Hash(challenge_D || challenge_C)
/// - ê = ẽ + e · challenge
/// - r̂1 = r̃1 - r1 · challenge
/// - r̂3 = r̃3 - r3 · challenge
/// - m̂_i = m̃_i + m_i · challenge (for i ∈ U)
///
/// Client completes the proof using device response
/// Returns: DeviceProof
pub fn proof_gen2<CS>(
    pre_comp: &ProofPreComputation,
    usk_hat: &Scalar,
    r_hat: &Scalar,
    challenge_d: &Scalar,
    challenge_c: &Scalar,
) -> Result<DeviceProof, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    // Calculate combined challenge = Hash(challenge_D || challenge_C)
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&challenge_d.to_bytes_be());
    challenge_input.extend_from_slice(&challenge_c.to_bytes_be());

    let challenge = hash_to_scalar::<CS>(&challenge_input, b"combined_challenge")?;

    // Calculate hat values: ê = ẽ + e · challenge, r̂1 = r̃1 - r1 · challenge, etc.
    let e_hat = pre_comp.e_tilde + pre_comp.e * challenge;
    let r1_hat = pre_comp.r1_tilde - pre_comp.r1 * challenge;
    let r3_hat = pre_comp.r3_tilde - pre_comp.r3 * challenge;

    let mut m_hat = Vec::new();
    for (i, m_tilde) in pre_comp.m_tilde.iter().enumerate() {
        m_hat.push(m_tilde + pre_comp.m_hidden[i] * challenge);
    }

    Ok(DeviceProof {
        a_bar: pre_comp.a_bar,
        b_bar: pre_comp.b_bar,
        d: pre_comp.d,
        e_hat,
        r1_hat,
        r3_hat,
        m_hat,
        usk_hat: *usk_hat,
        r_hat: *r_hat,
        challenge,
        challenge_d: *challenge_d,
    })
}

/// VerifyProof algorithm from VP presentation phase
///
/// Mathematical formulas:
/// - T1 = B̄^{challenge} · Ā^ê · D^{r̂1}
/// - B_V = g_1 · ∏_{i∈𝒟} h_i^{m_i}
/// - T2 = B_V^{challenge} · D^{r̂3} · h_c^{r̂} · h_0^{-ûsk} · ∏_{i∈U} h_i^{m̂_i}
/// - challenge' = Hash(challenge_D || Hash(Ā || B̄ || D || T1 || T2 || |𝒟| || 𝒟 || {m_i}_{i∈𝒟} || nonce_V))
/// - Verify: (challenge == challenge') ∧ (e(Ā, pk) == e(B̄, g_2))
///
/// Returns: Ok(()) if valid, Error otherwise
pub fn verify_proof<CS>(
    prm: &Generators,
    pk: &BBSplusPublicKey,
    disclosed_messages: &[(usize, BBSplusMessage)],
    nonce_v: &[u8],
    proof: &DeviceProof,
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    // Calculate T1 = B̄^{challenge} · Ā^ê · D^{r̂1}
    let t1 = proof.b_bar * proof.challenge + proof.a_bar * proof.e_hat + proof.d * proof.r1_hat;

    // Calculate B_V = g_1 · ∏_{i∈𝒟} h_i^{m_i}
    let mut b_v = prm.g1_base_point;
    let h_points = &prm.values[2..];

    for (idx, msg) in disclosed_messages {
        if *idx < h_points.len() {
            b_v = b_v + h_points[*idx] * msg.value;
        }
    }

    // Verify: B_V^{challenge} · D^{r̂3} · h_0^{ûsk} · h_c^{r̂} · ∏_{i∈U} h_i^{m̂_i} = T2
    // Using consistent generators: h_0 for usk, h_c for r
    let h_c = prm.values.get(0).ok_or(Error::NotEnoughGenerators)?;
    let h_0 = prm.values.get(1).ok_or(Error::NotEnoughGenerators)?;

    let mut t2 =
        b_v * proof.challenge + proof.d * proof.r3_hat + h_0 * proof.usk_hat + h_c * proof.r_hat;

    // Add undisclosed message contributions
    // We need to iterate through messages in order and use m_hat for undisclosed ones
    let mut undisclosed_idx = 0;
    let disclosed_indexes: Vec<usize> = disclosed_messages.iter().map(|(idx, _)| *idx).collect();

    // The total number of messages is disclosed + undisclosed
    let total_messages = disclosed_messages.len() + proof.m_hat.len();

    for i in 0..total_messages {
        if !disclosed_indexes.contains(&i) {
            if undisclosed_idx < proof.m_hat.len() && i < h_points.len() {
                t2 = t2 + h_points[i] * proof.m_hat[undisclosed_idx];
                undisclosed_idx += 1;
            }
        }
    }

    // Recalculate challenge_C = Hash(Ā || B̄ || D || T1 || T2 || |𝒟| || 𝒟 || {m_i}_{i∈𝒟} || nonce_V)
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&proof.a_bar.to_affine().to_compressed());
    challenge_input.extend_from_slice(&proof.b_bar.to_affine().to_compressed());
    challenge_input.extend_from_slice(&proof.d.to_affine().to_compressed());
    challenge_input.extend_from_slice(&t1.to_affine().to_compressed());
    challenge_input.extend_from_slice(&t2.to_affine().to_compressed());
    challenge_input.extend_from_slice(&(disclosed_messages.len() as u64).to_le_bytes());

    for (idx, _) in disclosed_messages {
        challenge_input.extend_from_slice(&(*idx as u64).to_le_bytes());
    }

    for (_, msg) in disclosed_messages {
        challenge_input.extend_from_slice(&msg.value.to_bytes_be());
    }

    challenge_input.extend_from_slice(nonce_v);

    let challenge_c = hash_to_scalar::<CS>(&challenge_input, b"challenge")?;

    // Verify combined challenge = Hash(challenge_D || challenge_C)
    let mut challenge_verify_input = Vec::new();
    challenge_verify_input.extend_from_slice(&proof.challenge_d.to_bytes_be());
    challenge_verify_input.extend_from_slice(&challenge_c.to_bytes_be());

    let challenge_verify = hash_to_scalar::<CS>(&challenge_verify_input, b"combined_challenge")?;

    if challenge_verify != proof.challenge {
        return Err(Error::InvalidProofOfKnowledgeSignature);
    }

    // Verify pairing: e(Ā, pk) ?= e(B̄, g_2)
    let g2 = G2Projective::GENERATOR;

    let pairing1 = multi_miller_loop(&[(
        &proof.a_bar.to_affine(),
        &G2Prepared::from(pk.0.to_affine()),
    )])
    .final_exponentiation();

    let pairing2 =
        multi_miller_loop(&[(&proof.b_bar.to_affine(), &G2Prepared::from(g2.to_affine()))])
            .final_exponentiation();

    if pairing1 != pairing2 {
        return Err(Error::InvalidProofOfKnowledgeSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbsplus::{
        bbs_device::{blind_sign, commit_usk},
        ciphersuites::Bls12381Sha256,
        keys::BBSplusSecretKey,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_vp_presentation_flow() {
        let mut rng = StdRng::from_seed([2u8; 32]);

        // Setup
        let sk = BBSplusSecretKey(get_random(&mut rng));
        let pk = sk.public_key();

        // Create generators
        let prm = Generators::create::<Bls12381Sha256>(5, Some(Bls12381Sha256::API_ID));

        // Device secret key
        let usk = get_random(&mut rng);
        let nonce_i = b"test_nonce_issue";

        // Issue VC first
        let (_, commitment_with_proof, r) =
            commit_usk::<Bls12381Sha256, _>(&mut rng, &prm, &usk, nonce_i).unwrap();

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

        // Now test VP presentation
        let nonce_v = b"test_nonce_verify";
        let disclosed_indexes = vec![0, 2]; // Disclose first and third message

        // Step 1: CommitForProof
        let commit_output = commit_for_proof::<Bls12381Sha256, _>(&mut rng, &prm).unwrap();

        assert!(commit_output.h0_usk_tilde != G1Projective::IDENTITY);
        assert!(commit_output.hc_r_tilde != G1Projective::IDENTITY);

        // Step 2: ProofGen1
        let (pre_comp, challenge_c) = proof_gen1::<Bls12381Sha256, _>(
            &mut rng,
            &prm,
            &pk,
            &signature,
            &commitment_with_proof.commitment,
            &messages,
            &disclosed_indexes,
            nonce_v,
            &commit_output,
        )
        .unwrap();

        assert!(pre_comp.a_bar != G1Projective::IDENTITY);
        assert!(pre_comp.b_bar != G1Projective::IDENTITY);
        assert!(pre_comp.d != G1Projective::IDENTITY);

        // Step 3: RespondForProof
        let (usk_hat, r_hat) =
            respond_for_proof::<Bls12381Sha256>(&prm, &usk, &r, &commit_output, &challenge_c)
                .unwrap();

        // Step 4: ProofGen2
        let proof = proof_gen2::<Bls12381Sha256>(
            &pre_comp,
            &usk_hat,
            &r_hat,
            &commit_output.challenge_d,
            &challenge_c,
        )
        .unwrap();

        // Step 5: VerifyProof
        let disclosed_messages = vec![(0, messages[0].clone()), (2, messages[2].clone())];

        let result =
            verify_proof::<Bls12381Sha256>(&prm, &pk, &disclosed_messages, nonce_v, &proof);

        assert!(result.is_ok(), "Proof verification should succeed");
    }
}
