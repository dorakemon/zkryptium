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

use alloc::string::String;
#[cfg(feature = "thiserror")]
use thiserror::Error;

#[cfg_attr(feature = "thiserror", derive(Error))]
#[derive(Clone, Debug)]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("Error during keypair generation"))]
    KeyGenError(String),
    #[cfg_attr(feature = "thiserror", error("Invalid key"))]
    KeyDeserializationError,
    #[cfg_attr(
        feature = "thiserror",
        error("Error during computation of a Blind Signature")
    )]
    BlindSignError(String),
    #[cfg_attr(
        feature = "thiserror",
        error("Error during computation of a Signature")
    )]
    SignatureGenerationError(String),
    #[cfg_attr(feature = "thiserror", error("Not a valid Signature"))]
    InvalidSignature,
    #[cfg_attr(
        feature = "thiserror",
        error("Error during hash to scalar computation")
    )]
    HashToScalarError,
    #[cfg_attr(feature = "thiserror", error("Error mapping a message to scalar"))]
    MapMessageToScalarError,
    #[cfg_attr(feature = "thiserror", error("Not enough Generators"))]
    NotEnoughGenerators,
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coresign) in the `Note` at the end
    #[cfg_attr(feature = "thiserror", error(" A == Identity_G1"))]
    G1IdentityError,
    #[cfg_attr(feature = "thiserror", error("Error during deserialization"))]
    DeserializationError(String),
    #[cfg_attr(feature = "thiserror", error("Signature is not valid"))]
    SignatureVerificationError,
    #[cfg_attr(
        feature = "thiserror",
        error("Error during computation of a Proof of Knowledge of a Signature")
    )]
    ProofGenError(String),
    #[cfg_attr(
        feature = "thiserror",
        error("Error during computation of a Blind Proof of Knowledge of a Signature")
    )]
    BlindProofGenError(String),
    #[cfg_attr(feature = "thiserror", error("Unknown error"))]
    Unspecified,
    #[cfg_attr(feature = "thiserror", error("Signature update failed"))]
    UpdateSignatureError(String),
    #[cfg_attr(
        feature = "thiserror",
        error("Invalid Proof of Knowledge of a Signature")
    )]
    InvalidProofOfKnowledgeSignature,
    #[cfg_attr(
        feature = "thiserror",
        error("Proof of Knowledge of a Signature verification failed")
    )]
    PoKSVerificationError(String),
    #[cfg_attr(feature = "thiserror", error("This should NOT happen!"))]
    UnespectedError,
    #[cfg_attr(feature = "thiserror", error("Invalid commitment"))]
    InvalidCommitment,
    #[cfg_attr(feature = "thiserror", error("Invalid commitment proof"))]
    InvalidCommitmentProof,
    #[cfg_attr(feature = "thiserror", error("Failed to compute the blind challenge"))]
    ChallengeComputationFailed,
}

#[cfg(not(feature = "thiserror"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::KeyGenError(s) => write!(f, "Error during keypair generation: {}", s),
            Error::KeyDeserializationError => write!(f, "Invalid key"),
            Error::BlindSignError(s) => {
                write!(f, "Error during computation of a Blind Signature: {}", s)
            }
            Error::SignatureGenerationError(s) => {
                write!(f, "Error during computation of a Signature: {}", s)
            }
            Error::InvalidSignature => write!(f, "Not a valid Signature"),
            Error::HashToScalarError => write!(f, "Error during hash to scalar computation"),
            Error::MapMessageToScalarError => write!(f, "Error mapping a message to scalar"),
            Error::NotEnoughGenerators => write!(f, "Not enough Generators"),
            Error::G1IdentityError => write!(f, "A == Identity_G1"),
            Error::DeserializationError(s) => write!(f, "Error during deserialization: {}", s),
            Error::SignatureVerificationError => write!(f, "Signature is not valid"),
            Error::ProofGenError(s) => write!(
                f,
                "Error during computation of a Proof of Knowledge of a Signature: {}",
                s
            ),
            Error::BlindProofGenError(s) => write!(
                f,
                "Error during computation of a Blind Proof of Knowledge of a Signature: {}",
                s
            ),
            Error::Unspecified => write!(f, "Unknown error"),
            Error::UpdateSignatureError(s) => write!(f, "Signature update failed: {}", s),
            Error::InvalidProofOfKnowledgeSignature => {
                write!(f, "Invalid Proof of Knowledge of a Signature")
            }
            Error::PoKSVerificationError(s) => write!(
                f,
                "Proof of Knowledge of a Signature verification failed: {}",
                s
            ),
            Error::UnespectedError => write!(f, "This should NOT happen!"),
            Error::InvalidCommitment => write!(f, "Invalid commitment"),
            Error::InvalidCommitmentProof => write!(f, "Invalid commitment proof"),
            Error::ChallengeComputationFailed => write!(f, "Failed to compute the blind challenge"),
        }
    }
}
