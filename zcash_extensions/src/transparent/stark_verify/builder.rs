use std::ops::{Deref, DerefMut};

use zcash_primitives::{
    extensions::transparent::{ExtensionTxBuilder, FromPayload},
    transaction::components::tze::OutPoint,
};
use zcash_protocol::value::Zatoshis;

use crate::transparent::stark_verify::{
    error::Error,
    modes,
    precondition::Precondition,
    witness::Witness,
};

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
    /// Add an initialize precondition output to create a new program/channel.
    /// This output can later be spent by either initialize or stark_verify mode inputs.
    pub fn add_initialize_output(
        &mut self,
        value: Zatoshis,
        root: [u8; 32],
        os_program_hash: [u8; 32],
        bootloader_program_hash: [u8; 32],
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::initialize(root, os_program_hash, bootloader_program_hash))
            .map_err(StarkVerifyBuildError::BaseBuilderError)
    }

    /// Add an initialize witness input to spend an initialize precondition output.
    /// This mode doesn't require proof verification, just creates a new channel output.
    pub fn add_initialize_input(
        &mut self,
        prevout: (OutPoint, zcash_primitives::transaction::components::tze::TzeOut),
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        // Validate that the previous output has an initialize precondition
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(StarkVerifyBuildError::PrevoutParseFailure(parse_failure)),
            Ok(Precondition::Initialize(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, modes::initialize::MODE, prevout, move |_| {
                        Ok(Witness::initialize())
                    })
                    .map_err(StarkVerifyBuildError::BaseBuilderError)
            }
            Ok(_) => Err(StarkVerifyBuildError::PrevoutParseFailure(Error::ModeInvalid(prevout.1.precondition.mode))),
        }
    }

    /// Add a STARK verification precondition output to the transaction.
    pub fn add_stark_verify_output(
        &mut self,
        value: Zatoshis,
        root: [u8; 32],
        os_program_hash: [u8; 32],
        bootloader_program_hash: [u8; 32],
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::stark_verify(root, os_program_hash, bootloader_program_hash))
            .map_err(StarkVerifyBuildError::BaseBuilderError)
    }

    /// Add a STARK verification witness input to the transaction.
    pub fn add_stark_verify_input(
        &mut self,
        prevout: (OutPoint, zcash_primitives::transaction::components::tze::TzeOut),
        proof_data: Vec<u8>,
        with_pedersen: bool,
        proof_format: modes::verify::ProofFormat,
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        // Validate that the previous output has a stark_verify precondition
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(StarkVerifyBuildError::PrevoutParseFailure(parse_failure)),
            Ok(Precondition::StarkVerify(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, modes::verify::MODE, prevout, move |_| {
                        Ok(Witness::stark_verify(proof_data.clone(), with_pedersen, proof_format))
                    })
                    .map_err(StarkVerifyBuildError::BaseBuilderError)
            }
            Ok(_) => Err(StarkVerifyBuildError::PrevoutParseFailure(Error::ModeInvalid(prevout.1.precondition.mode))),
        }
    }
}
