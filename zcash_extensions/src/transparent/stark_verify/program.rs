use zcash_primitives::extensions::transparent::Extension;

use crate::transparent::stark_verify::{
    context::Context,
    error::Error,
    modes,
    precondition::Precondition,
    witness::Witness,
};

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
    /// For Initialize mode: Simply validates that the output precondition is specified correctly.
    /// For StarkVerify mode: Verifies a STARK proof embedded in the witness against the precondition.
    fn verify_inner(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Error> {
        match (precondition, witness) {
            (Precondition::Initialize(p), Witness::Initialize(w)) => {
                modes::initialize::verify_program(p, w, context)
            }
            (Precondition::StarkVerify(p), Witness::StarkVerify(w)) => {
                modes::verify::verify_program(p, w, context)
            }
            // Mismatched precondition/witness pairs
            _ => Err(Error::ModeInvalid(0)), // Mode 0 is arbitrary here; could add a new error variant
        }
    }
}
