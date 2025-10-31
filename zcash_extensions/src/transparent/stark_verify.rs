//! STARK proof verification TZE implementation.
//!
//! This extension enables verification of STARK proofs within Zcash transactions.
//! The extension validates STARK proofs embedded in transaction witnesses against
//! verification keys and public inputs specified in preconditions.
//!
//! For now, this is a minimal implementation that always succeeds, providing
//! the structural foundation for proper STARK verification.

use std::fmt;
use std::io::Read;
use std::ops::{Deref, DerefMut};

// Stwo Cairo imports for STARK verification
use bzip2::read::BzDecoder;
use cairo_air::utils::get_verification_output;
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_serialize::CairoDeserialize;

use zcash_primitives::{
    extensions::transparent::{Extension, ExtensionTxBuilder, FromPayload, ToPayload},
    transaction::components::tze::OutPoint,
};
use zcash_protocol::value::Zatoshis;

/// Types and constants used for Mode 0 (verify STARK proof)
pub mod verify {
    use starknet_ff::FieldElement;
    use stwo_cairo_serialize::{CairoDeserialize, CairoSerialize};

    pub const MODE: u32 = 0;

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
        /// Serialized Cairo proof data
        pub proof_data: Vec<u8>,
        /// Whether the proof includes Pedersen builtin
        pub with_pedersen: bool,
        /// TEMPORARY: Proof encoding format (to be removed once we settle on one format)
        pub proof_format: ProofFormat,
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
}

/// The precondition type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Precondition {
    Verify(verify::Precondition),
}

impl Precondition {
    /// Convenience constructor for verify precondition values.
    pub fn verify(root: [u8; 32], program_hash: [u8; 32]) -> Self {
        Precondition::Verify(verify::Precondition { root, program_hash })
    }
}

/// Errors that may be produced during parsing and verification of stark_verify
/// preconditions and witnesses.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Parse error indicating that the payload length was invalid.
    IllegalPayloadLength(usize),
    /// Verification error indicating that the specified mode was not recognized.
    ModeInvalid(u32),
    /// Decoding error indicating that the proof data could not be deserialized.
    DecodingProofFailed,
    /// Verification error indicating that the witness being verified did not
    /// satisfy the precondition.
    VerificationFailed,
    /// Verification error indicating that an unexpected number of TZE outputs was encountered.
    InvalidOutputQty(usize),
    /// Verification error indicating that the initial root from input doesn't match proof.
    InitialRootMismatch,
    /// Verification error indicating that the final root from output doesn't match proof.
    FinalRootMismatch,
    /// Verification error indicating that the output precondition could not be parsed.
    OutputPreconditionParseFailure,
    /// Verification error indicating that the proof public output could not be parsed.
    PublicOutputParseFailure,
    /// Verification error indicating that program hashes don't match across input, output, and proof.
    ProgramHashMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IllegalPayloadLength(sz) => {
                write!(f, "Illegal payload length for stark_verify: {}", sz)
            }
            Error::ModeInvalid(m) => write!(f, "Invalid TZE mode for stark_verify: {}", m),
            Error::DecodingProofFailed => write!(f, "Failed to decode/deserialize STARK proof"),
            Error::VerificationFailed => write!(f, "STARK verification failed"),
            Error::InvalidOutputQty(qty) => write!(f, "Incorrect number of TZE outputs: {}", qty),
            Error::InitialRootMismatch => write!(f, "Initial root from input doesn't match proof"),
            Error::FinalRootMismatch => write!(f, "Final root from output doesn't match proof"),
            Error::OutputPreconditionParseFailure => write!(f, "Failed to parse output precondition"),
            Error::PublicOutputParseFailure => write!(f, "Failed to parse proof public output"),
            Error::ProgramHashMismatch => write!(f, "Program hash mismatch between input, output, and proof"),
        }
    }
}

impl TryFrom<(u32, Precondition)> for Precondition {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (verify::MODE, Precondition::Verify(p)) => Ok(Precondition::Verify(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            verify::MODE => {
                // Expect 64 bytes: 32 for root + 32 for program_hash
                if payload.len() == 64 {
                    let mut root = [0u8; 32];
                    let mut program_hash = [0u8; 32];
                    root.copy_from_slice(&payload[0..32]);
                    program_hash.copy_from_slice(&payload[32..64]);
                    Ok(Precondition::verify(root, program_hash))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Precondition::Verify(p) => {
                let mut payload = Vec::with_capacity(64);
                payload.extend_from_slice(&p.root);
                payload.extend_from_slice(&p.program_hash);
                (verify::MODE, payload)
            }
        }
    }
}

/// The witness type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Witness {
    Verify(verify::Witness),
}

impl Witness {
    /// Convenience constructor for verify witness values.
    pub fn verify(proof_data: Vec<u8>, with_pedersen: bool, proof_format: verify::ProofFormat) -> Self {
        Witness::Verify(verify::Witness {
            proof_data,
            with_pedersen,
            proof_format,
        })
    }
}

impl TryFrom<(u32, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (verify::MODE, Witness::Verify(w)) => Ok(Witness::Verify(w)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            verify::MODE => {
                // Payload format: [with_pedersen (1 byte)] + [proof_format (1 byte)] + [proof_data]
                if payload.len() < 2 {
                    return Err(Error::IllegalPayloadLength(payload.len()));
                }

                let with_pedersen = payload[0] != 0;
                let proof_format = match payload[1] {
                    0 => verify::ProofFormat::JsonEnc,
                    1 => verify::ProofFormat::BinEnc,
                    _ => return Err(Error::IllegalPayloadLength(payload.len())),
                };
                let proof_data = payload[2..].to_vec();

                Ok(Witness::verify(proof_data, with_pedersen, proof_format))
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Verify(w) => {
                let mut payload = vec![
                    if w.with_pedersen { 1 } else { 0 },
                    match w.proof_format {
                        verify::ProofFormat::JsonEnc => 0,
                        verify::ProofFormat::BinEnc => 1,
                    },
                ];
                payload.extend_from_slice(&w.proof_data);
                (verify::MODE, payload)
            }
        }
    }
}

/// This trait defines the context information that the stark_verify extension
/// requires from a consensus node integrating this extension.
///
/// This context type provides accessors to information relevant to a single
/// transaction being validated by the extension.
pub trait Context {
    /// List of all TZE outputs in the transaction being validated by the extension.
    fn tx_tze_outputs(&self) -> &[zcash_primitives::transaction::components::tze::TzeOut];
}

/// Marker type for the stark_verify extension.
///
/// A value of this type will be used as the receiver for
/// `zcash_primitives::extensions::transparent::Extension` method invocations.
pub struct Program;

impl<C: Context> Extension<C> for Program {
    type Precondition = Precondition;
    type Witness = Witness;
    type Error = Error;

    /// Runs the program against the given precondition, witness, and context.
    ///
    /// Verifies a STARK proof embedded in the witness against the precondition.
    fn verify_inner(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Error> {
        match (precondition, witness) {
            (Precondition::Verify(p_input), Witness::Verify(w)) => {
                // 1. Get the input_initial_root and input_program_hash from the input precondition
                let input_initial_root = p_input.root;
                let input_program_hash = p_input.program_hash;

                // 2. Check that there is exactly one TZE output and get its precondition
                let outputs = context.tx_tze_outputs();
                let (output_final_root, output_program_hash) = match outputs {
                    [tze_out] => {
                        // Parse the output precondition to get the final root and program hash
                        match Precondition::from_payload(
                            tze_out.precondition.mode,
                            &tze_out.precondition.payload,
                        ) {
                            Ok(Precondition::Verify(p_output)) => (p_output.root, p_output.program_hash),
                            Err(_) => return Err(Error::OutputPreconditionParseFailure),
                        }
                    }
                    _ => return Err(Error::InvalidOutputQty(outputs.len())),
                };

                // 3. Parse the Cairo proof based on the encoding format
                let cairo_proof: CairoProof<Blake2sMerkleHasher> = match w.proof_format {
                    verify::ProofFormat::JsonEnc => {
                        // Parse the Cairo proof from JSON
                        let proof_str = std::str::from_utf8(&w.proof_data)
                            .map_err(|_| Error::DecodingProofFailed)?;

                        serde_json::from_str(proof_str).map_err(|_| Error::DecodingProofFailed)?
                    }
                    verify::ProofFormat::BinEnc => {
                        // Check if the data is bzip2-compressed (magic bytes 'BZ')
                        let proof_data = if w.proof_data.len() >= 2
                            && w.proof_data[0] == b'B'
                            && w.proof_data[1] == b'Z' {
                            // Data is bzip2-compressed, decompress it
                            let mut bz_decoder = BzDecoder::new(&w.proof_data[..]);
                            let mut decompressed = Vec::new();
                            bz_decoder
                                .read_to_end(&mut decompressed)
                                .map_err(|_| Error::DecodingProofFailed)?;
                            decompressed
                        } else {
                            // Data is not compressed, use as-is
                            w.proof_data.clone()
                        };

                        // Deserialize the Cairo proof from binary encoding
                        bincode::deserialize(&proof_data)
                            .map_err(|_| Error::DecodingProofFailed)?
                    }
                };

                // 4. Parse the proof's public output to get the roots and program hash from the proof
                let verification_output = get_verification_output(&cairo_proof.claim.public_data.public_memory);
                let public_output = &verification_output.output;

                // Deserialize BootloaderOutput (first 3 felts) and OsOutputHeader (next 10 felts)
                let mut iter = public_output.iter();
                let _bootloader_output = verify::BootloaderOutput::deserialize(&mut iter);
                let os_header = verify::OsOutputHeader::deserialize(&mut iter);

                // Convert FieldElements to bytes for comparison
                let proof_initial_root: [u8; 32] = os_header.initial_root.to_bytes_be()
                    .try_into()
                    .map_err(|_| Error::PublicOutputParseFailure)?;
                let proof_final_root: [u8; 32] = os_header.final_root.to_bytes_be()
                    .try_into()
                    .map_err(|_| Error::PublicOutputParseFailure)?;
                let proof_program_hash: [u8; 32] = os_header.os_program_hash.to_bytes_be()
                    .try_into()
                    .map_err(|_| Error::PublicOutputParseFailure)?;

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
                let preprocessed_trace = if w.with_pedersen {
                    PreProcessedTraceVariant::Canonical
                } else {
                    PreProcessedTraceVariant::CanonicalWithoutPedersen
                };

                // 9. Verify the STARK proof (matching cairo-prove CLI exactly)
                verify_cairo::<Blake2sMerkleChannel>(
                    cairo_proof,
                    preprocessed_trace,
                )
                .map_err(|_| Error::VerificationFailed)?;

                Ok(())
            }
        }
    }
}

/// Wrapper for [`zcash_primitives::transaction::builder::Builder`] that simplifies
/// constructing transactions that utilize the stark_verify extension.
pub struct StarkVerifyBuilder<B> {
    /// The wrapped transaction builder.
    pub txn_builder: B,

    /// The assigned identifier for this extension.
    pub extension_id: u32,
}

impl<B> Deref for StarkVerifyBuilder<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.txn_builder
    }
}

impl<B> DerefMut for StarkVerifyBuilder<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn_builder
    }
}

/// Errors that can occur in construction of transactions using `StarkVerifyBuilder`.
#[derive(Debug)]
pub enum StarkVerifyBuildError<E> {
    /// Wrapper for errors returned from the underlying `Builder`
    BaseBuilderError(E),
    /// Parse failure when reading precondition from previous output
    PrevoutParseFailure(Error),
}

/// Convenience methods for use with [`zcash_primitives::transaction::builder::Builder`]
/// for constructing transactions that utilize the stark_verify extension.
impl<'a, B: ExtensionTxBuilder<'a>> StarkVerifyBuilder<B> {
    /// Add a STARK verification precondition output to the transaction.
    pub fn add_stark_verify_output(
        &mut self,
        value: Zatoshis,
        root: [u8; 32],
        program_hash: [u8; 32],
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::verify(root, program_hash))
            .map_err(StarkVerifyBuildError::BaseBuilderError)
    }

    /// Add a STARK verification witness input to the transaction.
    pub fn add_stark_verify_input(
        &mut self,
        prevout: (OutPoint, zcash_primitives::transaction::components::tze::TzeOut),
        proof_data: Vec<u8>,
        with_pedersen: bool,
        proof_format: verify::ProofFormat,
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        // Validate that the previous output has a verify precondition
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(StarkVerifyBuildError::PrevoutParseFailure(parse_failure)),
            Ok(Precondition::Verify(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, verify::MODE, prevout, move |_| {
                        Ok(Witness::verify(proof_data.clone(), with_pedersen, proof_format))
                    })
                    .map_err(StarkVerifyBuildError::BaseBuilderError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        extensions::transparent::{self as tze, Extension, FromPayload, ToPayload},
        transaction::{
            TransactionData, TxVersion,
            components::tze::{Authorized, Bundle, OutPoint, TzeIn, TzeOut},
        },
    };
    use zcash_protocol::{consensus::BranchId, value::Zatoshis};

    use super::{Context, Precondition, Program, Witness, verify};

    /// Helper function to extract roots and program hash from a Cairo proof for testing
    fn extract_data_from_proof(proof_data: &[u8], _with_pedersen: bool, proof_format: verify::ProofFormat) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
        use bzip2::read::BzDecoder;
        use cairo_air::utils::get_verification_output;
        use cairo_air::CairoProof;
        use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
        use stwo_cairo_serialize::CairoDeserialize;
        use std::io::Read;

        // Parse the Cairo proof based on the encoding format
        let cairo_proof: CairoProof<Blake2sMerkleHasher> = match proof_format {
            verify::ProofFormat::JsonEnc => {
                let proof_str = std::str::from_utf8(proof_data)
                    .map_err(|_| "Failed to decode proof as UTF-8")?;
                serde_json::from_str(proof_str).map_err(|e| format!("Failed to parse JSON: {}", e))?
            }
            verify::ProofFormat::BinEnc => {
                // Check if the data is bzip2-compressed
                let actual_data = if proof_data.len() >= 2 && proof_data[0] == b'B' && proof_data[1] == b'Z' {
                    let mut bz_decoder = BzDecoder::new(proof_data);
                    let mut decompressed = Vec::new();
                    bz_decoder.read_to_end(&mut decompressed)
                        .map_err(|e| format!("Failed to decompress: {}", e))?;
                    decompressed
                } else {
                    proof_data.to_vec()
                };
                bincode::deserialize(&actual_data)
                    .map_err(|e| format!("Failed to deserialize bincode: {}", e))?
            }
        };

        // Parse the proof's public output
        let verification_output = get_verification_output(&cairo_proof.claim.public_data.public_memory);
        let public_output = &verification_output.output;

        let mut iter = public_output.iter();
        let _bootloader_output = verify::BootloaderOutput::deserialize(&mut iter);
        let os_header = verify::OsOutputHeader::deserialize(&mut iter);

        let initial_root: [u8; 32] = os_header.initial_root.to_bytes_be()
            .try_into()
            .map_err(|_| "Failed to convert initial_root to bytes")?;
        let final_root: [u8; 32] = os_header.final_root.to_bytes_be()
            .try_into()
            .map_err(|_| "Failed to convert final_root to bytes")?;
        let program_hash: [u8; 32] = os_header.os_program_hash.to_bytes_be()
            .try_into()
            .map_err(|_| "Failed to convert os_program_hash to bytes")?;

        Ok((initial_root, final_root, program_hash))
    }

    #[test]
    fn precondition_verify_round_trip() {
        let root = [7u8; 32];
        let program_hash = [9u8; 32];
        let mut data = Vec::new();
        data.extend_from_slice(&root);
        data.extend_from_slice(&program_hash);
        let p = Precondition::from_payload(verify::MODE, &data).unwrap();
        assert_eq!(p, Precondition::verify(root, program_hash));
        assert_eq!(p.to_payload(), (verify::MODE, data));
    }

    #[test]
    fn precondition_rejects_invalid_mode() {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&[7u8; 32]);
        data[32..].copy_from_slice(&[9u8; 32]);
        let p = Precondition::from_payload(99, &data);
        assert!(p.is_err());
    }

    #[test]
    fn precondition_rejects_invalid_payload_length() {
        // Empty payload should be rejected
        let p = Precondition::from_payload(verify::MODE, &[]);
        assert!(p.is_err());

        // Wrong length payload should be rejected
        let p = Precondition::from_payload(verify::MODE, &[1, 2, 3]);
        assert!(p.is_err());

        // 32 bytes should be rejected (need 64 bytes now)
        let p = Precondition::from_payload(verify::MODE, &[0u8; 32]);
        assert!(p.is_err());

        // 63 bytes should be rejected
        let p = Precondition::from_payload(verify::MODE, &[0u8; 63]);
        assert!(p.is_err());

        // 65 bytes should be rejected
        let p = Precondition::from_payload(verify::MODE, &[0u8; 65]);
        assert!(p.is_err());
    }

    #[test]
    fn witness_verify_round_trip() {
        let proof_data = b"test proof data".to_vec();
        let with_pedersen = false;
        let proof_format = verify::ProofFormat::JsonEnc;

        // Create payload: [with_pedersen flag] + [proof_format] + [proof_data]
        let mut payload = vec![
            if with_pedersen { 1 } else { 0 },
            match proof_format {
                verify::ProofFormat::JsonEnc => 0,
                verify::ProofFormat::BinEnc => 1,
            },
        ];
        payload.extend_from_slice(&proof_data);

        let w = Witness::from_payload(verify::MODE, &payload).unwrap();
        assert_eq!(w, Witness::verify(proof_data.clone(), with_pedersen, proof_format));
        assert_eq!(w.to_payload(), (verify::MODE, payload));
    }

    #[test]
    fn witness_rejects_invalid_mode() {
        let w = Witness::from_payload(99, &[]);
        assert!(w.is_err());
    }

    #[test]
    fn witness_accepts_valid_payload() {
        // Valid payload with flag and data
        let w = Witness::from_payload(verify::MODE, &[0, 1, 2, 3]);
        assert!(w.is_ok());
    }

    #[test]
    fn witness_rejects_empty_payload() {
        // Empty payload should be rejected (needs at least 2 bytes: pedersen flag + format byte)
        let w = Witness::from_payload(verify::MODE, &[]);
        assert!(w.is_err());
        // Single byte should also be rejected
        let w = Witness::from_payload(verify::MODE, &[0]);
        assert!(w.is_err());
    }

    /// Dummy context for testing
    struct Ctx<'a> {
        tx: &'a zcash_primitives::transaction::Transaction,
    }

    impl<'a> Context for Ctx<'a> {
        fn tx_tze_outputs(&self) -> &[zcash_primitives::transaction::components::tze::TzeOut] {
            match self.tx.tze_bundle() {
                Some(b) => &b.vout,
                None => &[],
            }
        }
    }

    #[test]
    fn stark_verify_program_succeeds() {
        // Use dummy roots and program hash for testing
        let initial_root = [1u8; 32];
        let final_root = [2u8; 32];
        let program_hash = [3u8; 32];

        // Create a simple transaction with STARK verify TZE input and output
        let out_a = TzeOut {
            value: Zatoshis::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(initial_root, program_hash)),
        };

        let tx_a = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out_a],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Create spending transaction with a dummy witness and output (just for structural test)
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx_a.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify(vec![1, 2, 3], false, verify::ProofFormat::JsonEnc)),
        };

        let out_b = TzeOut {
            value: Zatoshis::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(final_root, program_hash)),
        };

        let tx_b = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_witness],
                vout: vec![out_b],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Verify the spend - this should fail with dummy data
        let ctx = Ctx { tx: &tx_b };
        let result = Program.verify(
            &tx_a.tze_bundle().unwrap().vout[0].precondition,
            &tx_b.tze_bundle().unwrap().vin[0].witness,
            &ctx,
        );
        // Dummy proof data should fail verification
        assert!(result.is_err());
    }

    /// This test demonstrates the full STARK verification integration using actual transactions.
    ///
    /// NOTE: Currently ignored because the all_opcode_components proof is a simple Cairo program
    /// proof without the Starknet OS header structure (BootloaderOutput + OsOutputHeader).
    /// The stark_verify extension now requires proofs with OS headers to verify state roots.
    /// Use verify_proof_sepolia test instead, which uses a real Starknet block proof.
    #[test]
    #[ignore]
    fn verify_proof_all_opcode_components() {
        // Load the embedded proof from test fixtures
        //
        // Generated using this command inside stwo-cairo stwo_cairo_prover crate:
        // ./target/release/run_and_prove \
        //   --program ./test_data/test_prove_verify_all_opcode_components/compiled.json \
        //   --proof_path example_proof.json \
        //   --verify
        let proof_str = include_str!("../../tests/fixtures/all_opcode_components_proof.json");
        let proof_data = proof_str.as_bytes().to_vec();

        // Extract roots and program hash from the proof
        let (initial_root, final_root, program_hash) = extract_data_from_proof(
            &proof_data,
            true,
            verify::ProofFormat::JsonEnc
        ).expect("Failed to extract data from proof");

        //
        // Create a transaction with a STARK verification precondition output
        //
        let out = TzeOut {
            value: Zatoshis::from_u64(100000).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(initial_root, program_hash)),
        };

        let tx_a = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        //
        // Create a spending transaction with the STARK proof witness and output with final root
        //
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx_a.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify(proof_data, true, verify::ProofFormat::JsonEnc)),
        };

        let out_b = TzeOut {
            value: Zatoshis::from_u64(100000).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(final_root, program_hash)),
        };

        let tx_b = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_witness],
                vout: vec![out_b],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        //
        // Verify the spending transaction using the full verification path
        //
        let ctx = Ctx { tx: &tx_b };
        let result = Program.verify(
            &tx_a.tze_bundle().unwrap().vout[0].precondition,
            &tx_b.tze_bundle().unwrap().vin[0].witness,
            &ctx,
        );

        // The proof should verify successfully
        assert!(
            result.is_ok(),
            "STARK proof verification failed: {:?}",
            result.err()
        );
    }

    /// This test demonstrates STARK proof verification from Starknet Sepolia network.
    #[test]
    fn verify_proof_sepolia() {
        // Load the compressed proof from test fixtures
        //
        // Generated using this command inside Ztarknet/gpp:
        // cargo run -- -b 2725346 -n sepolia
        let proof_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proof-sepolia-2725346.bz");
        let proof_data = std::fs::read(proof_file)
            .expect("Failed to read compressed proof file");

        // Extract roots and program hash from the proof
        let (initial_root, final_root, program_hash) = extract_data_from_proof(
            &proof_data,
            true,
            verify::ProofFormat::BinEnc
        ).expect("Failed to extract data from proof");

        // Create a transaction with a STARK verification precondition output
        let out = TzeOut {
            value: Zatoshis::from_u64(100000).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(initial_root, program_hash)),
        };

        let tx_a = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Create a spending transaction with the STARK proof witness (binary encoded) and output with final root
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx_a.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify(proof_data, true, verify::ProofFormat::BinEnc)),
        };

        let out_b = TzeOut {
            value: Zatoshis::from_u64(100000).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(final_root, program_hash)),
        };

        let tx_b = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_witness],
                vout: vec![out_b],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Verify the spending transaction using the full verification path
        let ctx = Ctx { tx: &tx_b };
        let result = Program.verify(
            &tx_a.tze_bundle().unwrap().vout[0].precondition,
            &tx_b.tze_bundle().unwrap().vin[0].witness,
            &ctx,
        );
        // The proof should verify successfully
        assert!(
            result.is_ok(),
            "STARK proof verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_inner_basic_flow() {
        // This test demonstrates that the verify_inner function is properly wired up
        // and can parse/verify proofs. It expects failure with invalid proof data,
        // which confirms the verification logic is running.

        let initial_root = [1u8; 32];
        let final_root = [2u8; 32];
        let program_hash = [3u8; 32];

        // Create a transaction with TZE output for context
        let out = TzeOut {
            value: Zatoshis::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify(final_root, program_hash)),
        };

        let tx = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        let ctx = Ctx { tx: &tx };
        let precondition = Precondition::verify(initial_root, program_hash);

        // Test 1: Invalid JSON should fail at parsing stage
        let invalid_json = b"{invalid json}".to_vec();
        let witness = Witness::verify(invalid_json, false, verify::ProofFormat::JsonEnc);
        let result = Program.verify_inner(&precondition, &witness, &ctx);
        assert!(
            result.is_err(),
            "Invalid JSON should fail verification"
        );

        // Test 2: Valid JSON but not a proof should fail
        let not_a_proof = br#"{"foo": "bar"}"#.to_vec();
        let witness = Witness::verify(not_a_proof, false, verify::ProofFormat::JsonEnc);
        let result = Program.verify_inner(&precondition, &witness, &ctx);
        assert!(
            result.is_err(),
            "Non-proof JSON should fail verification"
        );

        // This confirms that:
        // 1. Witness data is being passed through correctly
        // 2. JSON parsing is attempted
        // 3. Verification logic is invoked
        // 4. Errors are properly propagated
    }
}
