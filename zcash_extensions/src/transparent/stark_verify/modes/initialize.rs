//! Types and constants used for Mode 0 (initialize program/channel)

use zcash_primitives::extensions::transparent::FromPayload;

use crate::transparent::stark_verify::{context::Context, error::Error};

pub const MODE: u32 = 0;

/// Precondition for channel initialization.
/// Contains the initial state root and program hash for a new channel.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Precondition {
    /// State root (32 bytes)
    pub root: [u8; 32],
    /// Program hash (32 bytes)
    pub program_hash: [u8; 32],
}

impl Precondition {
    /// Deserialize a precondition from a payload.
    /// Expects 64 bytes: 32 for root + 32 for program_hash.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() == 64 {
            let mut root = [0u8; 32];
            let mut program_hash = [0u8; 32];
            root.copy_from_slice(&payload[0..32]);
            program_hash.copy_from_slice(&payload[32..64]);
            Ok(Precondition { root, program_hash })
        } else {
            Err(Error::IllegalPayloadLength(payload.len()))
        }
    }

    /// Serialize the precondition to a payload.
    /// Returns 64 bytes: 32 for root + 32 for program_hash.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.root);
        payload.extend_from_slice(&self.program_hash);
        payload
    }
}

/// Witness for channel initialization.
/// Empty witness as initialization doesn't require proof verification.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Witness;

impl Witness {
    /// Deserialize a witness from a payload.
    /// Expects an empty payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        if payload.is_empty() {
            Ok(Witness)
        } else {
            Err(Error::IllegalPayloadLength(payload.len()))
        }
    }

    /// Serialize the witness to a payload.
    /// Returns an empty payload.
    pub fn to_payload(&self) -> Vec<u8> {
        vec![]
    }
}

/// Verify the initialize mode precondition and witness.
///
/// Initialize mode validates that there is exactly one TZE output with a precondition.
/// The output can be either Initialize or StarkVerify mode.
pub fn verify_program(
    _precondition: &Precondition,
    _witness: &Witness,
    context: &impl Context,
) -> Result<(), Error> {
    // Initialize mode: Validate that there is exactly one TZE output with a precondition
    let outputs = context.tx_tze_outputs();
    match outputs {
        [tze_out] => {
            // Parse the output precondition to verify it's valid
            // The output can be either Initialize or StarkVerify mode
            // Import the top-level Precondition to parse the output
            match crate::transparent::stark_verify::Precondition::from_payload(
                tze_out.precondition.mode,
                &tze_out.precondition.payload,
            ) {
                Ok(crate::transparent::stark_verify::Precondition::Initialize(_))
                | Ok(crate::transparent::stark_verify::Precondition::StarkVerify(_)) => {
                    // Valid output precondition
                    // For Initialize mode, we don't verify any proof, just ensure the structure is valid
                    // The input precondition specifies the initial state that can later be verified
                    Ok(())
                }
                Err(_) => Err(Error::OutputPreconditionParseFailure),
            }
        }
        _ => Err(Error::InvalidOutputQty(outputs.len())),
    }
}
