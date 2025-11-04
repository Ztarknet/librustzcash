//! Types and constants used for Mode 1 (verify STARK proof)

use std::io::Read;

use bzip2::read::BzDecoder;
use cairo_air::utils::get_verification_output;
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use starknet_ff::FieldElement;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_serialize::{CairoDeserialize, CairoSerialize};
use zcash_primitives::extensions::transparent::FromPayload;

use crate::transparent::stark_verify::{context::Context, error::Error};

pub const MODE: u32 = 1;

/// Proof encoding format
/// TEMPORARY: This field will be removed once we settle on a single encoding format
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ProofFormat {
    /// JSON-encoded proof data
    JsonEnc,
    /// Binary-encoded proof data (bincode)
    BinEnc,
}

/// Precondition for STARK verification.
/// Contains the state root and program hash that must be verified against the proof.
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

/// Bootloader output structure from Cairo proof
#[derive(Debug, Clone, CairoSerialize, CairoDeserialize)]
pub struct BootloaderOutput {
    pub n_tasks: usize,
    pub task_output_size: usize,
    pub task_program_hash: FieldElement,
}

/// OS output header structure containing state roots and block information
#[derive(Debug, Clone, CairoSerialize, CairoDeserialize)]
pub struct OsOutputHeader {
    pub initial_root: FieldElement,
    pub final_root: FieldElement,
    pub prev_block_number: FieldElement,
    pub new_block_number: FieldElement,
    pub prev_block_hash: FieldElement,
    pub new_block_hash: FieldElement,
    pub os_program_hash: FieldElement,
    pub starknet_os_config_hash: FieldElement,
    pub use_kzg_da: FieldElement,
    pub full_output: FieldElement,
}

/// Witness containing STARK proof.
/// Contains the serialized Cairo proof data and metadata for verification.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Whether the proof includes Pedersen builtin
    pub with_pedersen: bool,
    /// TEMPORARY: Proof encoding format (to be removed once we settle on one format)
    pub proof_format: ProofFormat,
    /// Serialized Cairo proof data
    pub proof_data: Vec<u8>,
}

// Manual PartialEq implementation since we need to compare the struct
impl PartialEq for Witness {
    fn eq(&self, other: &Self) -> bool {
        self.proof_data == other.proof_data
            && self.with_pedersen == other.with_pedersen
            && self.proof_format == other.proof_format
    }
}

impl Eq for Witness {}

impl Witness {
    /// Deserialize a witness from a payload.
    /// Payload format: [with_pedersen (1 byte)] + [proof_format (1 byte)] + [proof_data]
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < 2 {
            return Err(Error::IllegalPayloadLength(payload.len()));
        }

        let with_pedersen = payload[0] != 0;
        let proof_format = match payload[1] {
            0 => ProofFormat::JsonEnc,
            1 => ProofFormat::BinEnc,
            _ => return Err(Error::IllegalPayloadLength(payload.len())),
        };
        let proof_data = payload[2..].to_vec();

        Ok(Witness {
            with_pedersen,
            proof_format,
            proof_data,
        })
    }

    /// Serialize the witness to a payload.
    /// Returns: [with_pedersen (1 byte)] + [proof_format (1 byte)] + [proof_data]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = vec![
            if self.with_pedersen { 1 } else { 0 },
            match self.proof_format {
                ProofFormat::JsonEnc => 0,
                ProofFormat::BinEnc => 1,
            },
        ];
        payload.extend_from_slice(&self.proof_data);
        payload
    }
}

/// Verify the STARK proof against the precondition.
///
/// This performs full STARK proof verification:
/// 1. Parses the Cairo proof from the witness
/// 2. Extracts public outputs (initial/final roots, program hash)
/// 3. Validates roots and program hash against input/output preconditions
/// 4. Verifies the STARK proof cryptographically
pub fn verify_program(
    precondition: &Precondition,
    witness: &Witness,
    context: &impl Context,
) -> Result<(), Error> {
    // 1. Get the input_initial_root and input_program_hash from the input precondition
    let input_initial_root = precondition.root;
    let input_program_hash = precondition.program_hash;

    // 2. Check that there is exactly one TZE output and get its precondition
    let outputs = context.tx_tze_outputs();
    let (output_final_root, output_program_hash) = match outputs {
        [tze_out] => {
            // Parse the output precondition to get the final root and program hash
            match crate::transparent::stark_verify::Precondition::from_payload(
                tze_out.precondition.mode,
                &tze_out.precondition.payload,
            ) {
                Ok(crate::transparent::stark_verify::Precondition::StarkVerify(p_output)) => {
                    (p_output.root, p_output.program_hash)
                }
                Ok(crate::transparent::stark_verify::Precondition::Initialize(_)) => {
                    return Err(Error::OutputPreconditionParseFailure)
                }
                Err(_) => return Err(Error::OutputPreconditionParseFailure),
            }
        }
        _ => return Err(Error::InvalidOutputQty(outputs.len())),
    };

    // 3. Parse the Cairo proof based on the encoding format
    let cairo_proof: CairoProof<Blake2sMerkleHasher> = match witness.proof_format {
        ProofFormat::JsonEnc => {
            // Parse the Cairo proof from JSON
            let proof_str = std::str::from_utf8(&witness.proof_data)
                .map_err(|_| Error::DecodingProofFailed)?;

            serde_json::from_str(proof_str).map_err(|_| Error::DecodingProofFailed)?
        }
        ProofFormat::BinEnc => {
            // Check if the data is bzip2-compressed (magic bytes 'BZ')
            let proof_data = if witness.proof_data.len() >= 2
                && witness.proof_data[0] == b'B'
                && witness.proof_data[1] == b'Z'
            {
                // Data is bzip2-compressed, decompress it
                let mut bz_decoder = BzDecoder::new(&witness.proof_data[..]);
                let mut decompressed = Vec::new();
                bz_decoder
                    .read_to_end(&mut decompressed)
                    .map_err(|_| Error::DecodingProofFailed)?;
                decompressed
            } else {
                // Data is not compressed, use as-is
                witness.proof_data.clone()
            };

            // Deserialize the Cairo proof from binary encoding
            bincode::deserialize(&proof_data).map_err(|_| Error::DecodingProofFailed)?
        }
    };

    // 4. Parse the proof's public output to get the roots and program hash from the proof
    let verification_output =
        get_verification_output(&cairo_proof.claim.public_data.public_memory);
    let public_output = &verification_output.output;

    // Deserialize BootloaderOutput (first 3 felts) and OsOutputHeader (next 10 felts)
    let mut iter = public_output.iter();
    let _bootloader_output = BootloaderOutput::deserialize(&mut iter);
    let os_header = OsOutputHeader::deserialize(&mut iter);

    // Convert FieldElements to bytes for comparison
    let proof_initial_root: [u8; 32] = os_header.initial_root.to_bytes_be();
    let proof_final_root: [u8; 32] = os_header.final_root.to_bytes_be();
    let proof_program_hash: [u8; 32] = os_header.os_program_hash.to_bytes_be();

    // 5. Verify that input_initial_root == os_header.initial_root
    if input_initial_root != proof_initial_root {
        return Err(Error::InitialRootMismatch);
    }

    // 6. Verify that output_final_root == os_header.final_root
    if output_final_root != proof_final_root {
        return Err(Error::FinalRootMismatch);
    }

    // 7. Verify program hash consistency across input, output, and proof
    if input_program_hash != output_program_hash || input_program_hash != proof_program_hash {
        return Err(Error::ProgramHashMismatch);
    }

    // 8. Determine the preprocessed trace variant based on Pedersen flag
    let preprocessed_trace = if witness.with_pedersen {
        PreProcessedTraceVariant::Canonical
    } else {
        PreProcessedTraceVariant::CanonicalWithoutPedersen
    };

    // 9. Verify the STARK proof (matching cairo-prove CLI exactly)
    verify_cairo::<Blake2sMerkleChannel>(cairo_proof, preprocessed_trace)
        .map_err(|_| Error::VerificationFailed)?;

    Ok(())
}
