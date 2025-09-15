# Device-Separated BBS+ Signature Protocol

## Overview

This implementation provides a device-separated variant of the BBS+ signature scheme, where cryptographic operations are split between a secure device (holding private keys) and a client (performing most computations). This architecture is particularly suitable for hardware security modules, smart cards, or trusted execution environments.

## Protocol Architecture

The protocol consists of two main phases:

1. **VC Issuance Phase** - Credential issuance with blind signing
2. **VP Presentation Phase** - Zero-knowledge proof generation for selective disclosure

## Key Features

- **Device isolation**: Private keys (`usk`) never leave the secure device
- **Minimal device computation**: Device performs only essential scalar operations
- **Constant-time device operations**: Device computation time is independent of the number of attributes
- **Two-round protocols**: Both phases require exactly 2 round-trips between device and client

## VC Issuance Phase

### CommitUsk (Device)
Generates a commitment to the device's secret key with a proof of correctness.

**Mathematical formula:**
```
r ← $Z_p, issueId ← {0,1}*
com = h_0^usk · h_c^r
π_com = SPK{(usk, r): com = h_0^usk · h_c^r}(nonce_I)
```

**Returns:** `(issueId, commitment, proof, r)`

### VerifyCommitUsk (Issuer)
Verifies the zero-knowledge proof that the commitment is correctly formed.

**Returns:** Success/Failure

### BlindSign (Issuer)
Issues a BBS+ signature on the commitment and messages without seeing `usk`.

**Mathematical formula:**
```
e ← $Z_p
A = (g_1 · com · ∏_{i∈L} h_i^{m_i})^{1/(sk+e)}
```

**Returns:** `BBSplusDeviceSignature (A, e)`

### Verify (Client)
Verifies the blind signature is valid.

**Mathematical formula:**
```
e(A, pk · g_2^e) = e(g_1 · com · ∏_{i∈L} h_i^{m_i}, g_2)
```

**Returns:** Success/Failure

## VP Presentation Phase

### Protocol Flow

The VP presentation phase involves 4 algorithms executed in sequence:

1. **CommitForProof** (Device) → Generates random commitments
2. **ProofGen1** (Client) → Creates proof skeleton and challenge
3. **RespondForProof** (Device) → Computes response values
4. **ProofGen2** (Client) → Completes the proof
5. **VerifyProof** (Verifier) → Verifies the zero-knowledge proof

### CommitForProof (Device)

**Mathematical formula:**
```
ũsk, r̃, challenge_D ← $Z_p
return (ũsk, r̃, challenge_D, h_0^ũsk, h_c^r̃)
```

Device stores `(ũsk, r̃, challenge_D)` and sends `(challenge_D, h_0^ũsk, h_c^r̃)` to client.

### ProofGen1 (Client)

**Mathematical formula:**
```
B = g_1 · com · ∏_{i∈L} h_i^{m_i}
r1, r2 ← $Z_p, r3 = 1/r2
D = B^{r2}, Ā = A^{r1·r2}, B̄ = Ā^{-e} · D^{r1}
ẽ, r̃1, r̃3, {m̃_i}_{i∈U} ← $Z_p
T1 = Ā^ẽ · D^{r̃1}
T2 = D^{r̃3} · h_0^ũsk · h_c^r̃ · ∏_{i∈U} h_i^{m̃_i}
challenge_C = Hash(Ā || B̄ || D || T1 || T2 || |𝒟| || 𝒟 || {m_i}_{i∈𝒟} || nonce_V)
```

**Returns:** `(proof_precomputation, challenge_C)`

### RespondForProof (Device)

**Mathematical formula:**
```
challenge = Hash(challenge_D || challenge_C)
ûsk = ũsk + usk · challenge
r̂ = r̃ + r · challenge
```

Device deletes `(ũsk, r̃, challenge_D)` and returns `(ûsk, r̂)` to client.

### ProofGen2 (Client)

**Mathematical formula:**
```
challenge = Hash(challenge_D || challenge_C)
ê = ẽ + e · challenge
r̂1 = r̃1 - r1 · challenge
r̂3 = r̃3 - r3 · challenge
m̂_i = m̃_i + m_i · challenge (for i ∈ U)
```

**Returns:** Complete proof `π`

### VerifyProof (Verifier)

**Mathematical formula:**
```
T1 = B̄^{challenge} · Ā^ê · D^{r̂1}
B_V = g_1 · ∏_{i∈𝒟} h_i^{m_i}
T2 = B_V^{challenge} · D^{r̂3} · h_c^{r̂} · h_0^{ûsk} · ∏_{i∈U} h_i^{m̂_i}
challenge' = Hash(challenge_D || Hash(Ā || B̄ || D || T1 || T2 || |𝒟| || 𝒟 || {m_i}_{i∈𝒟} || nonce_V))
```

**Verifies:**
- `challenge == challenge'`
- `e(Ā, pk) == e(B̄, g_2)`

## Generator Assignment

The protocol uses consistent generator assignment throughout:
- `h_0` is used for the device secret key (`usk`)
- `h_c` is used for the randomness (`r`)
- `h_i` (i ≥ 2) are used for message attributes

This ensures consistency between the VC issuance and VP presentation phases.

## Implementation Files

- `src/bbsplus/bbs_device.rs` - VC issuance phase implementation
- `src/bbsplus/bbs_proof_device.rs` - VP presentation phase implementation

## Usage Example

```rust
use zkryptium::bbsplus::{
    bbs_device::{commit_usk, verify_commit_usk, blind_sign, verify},
    bbs_proof_device::{commit_for_proof, proof_gen1, respond_for_proof, proof_gen2, verify_proof},
    ciphersuites::Bls12381Sha256,
    generators::Generators,
    keys::BBSplusSecretKey,
};

// VC Issuance
let (issue_id, commitment_with_proof, r) = 
    commit_usk::<Bls12381Sha256, _>(&mut rng, &prm, &usk, nonce_i)?;

verify_commit_usk::<Bls12381Sha256>(&prm, &commitment_with_proof, nonce_i)?;

let signature = blind_sign::<Bls12381Sha256, _>(
    &mut rng, &prm, &sk, &messages, &commitment_with_proof.commitment)?;

verify::<Bls12381Sha256>(&prm, &pk, &signature, &commitment_with_proof.commitment, &messages)?;

// VP Presentation
let commit_output = commit_for_proof::<Bls12381Sha256, _>(&mut rng, &prm)?;

let (pre_comp, challenge_c) = proof_gen1::<Bls12381Sha256, _>(
    &mut rng, &prm, &pk, &signature, &commitment, &messages, 
    &disclosed_indexes, nonce_v, &commit_output)?;

let (usk_hat, r_hat) = respond_for_proof::<Bls12381Sha256>(
    &prm, &usk, &r, &commit_output, &challenge_c)?;

let proof = proof_gen2::<Bls12381Sha256>(
    &pre_comp, &usk_hat, &r_hat, &commit_output.challenge_d, &challenge_c)?;

verify_proof::<Bls12381Sha256>(&prm, &pk, &disclosed_messages, nonce_v, &proof)?;
```

## Testing

The implementation includes comprehensive tests for both phases:

```bash
# Run VC issuance test
cargo test --lib bbsplus::bbs_device::tests::test_vc_issuance_flow

# Run VP presentation test  
cargo test --lib bbsplus::bbs_proof_device::tests::test_vp_presentation_flow

# Run all BBS device tests
cargo test --lib bbsplus::bbs
```