use zcash_primitives::extensions::transparent::{FromPayload, ToPayload};

use crate::transparent::stark_verify::{error::Error, modes};

/// The precondition type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Precondition {
    Initialize(modes::initialize::Precondition),
    StarkVerify(modes::verify::Precondition),
}

impl Precondition {
    /// Convenience constructor for initialize precondition values.
    pub fn initialize(root: [u8; 32], program_hash: [u8; 32]) -> Self {
        Precondition::Initialize(modes::initialize::Precondition { root, program_hash })
    }

    /// Convenience constructor for stark_verify precondition values.
    pub fn stark_verify(root: [u8; 32], program_hash: [u8; 32]) -> Self {
        Precondition::StarkVerify(modes::verify::Precondition { root, program_hash })
    }
}

impl TryFrom<(u32, Precondition)> for Precondition {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (modes::initialize::MODE, Precondition::Initialize(p)) => Ok(Precondition::Initialize(p)),
            (modes::verify::MODE, Precondition::StarkVerify(p)) => Ok(Precondition::StarkVerify(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            modes::initialize::MODE => {
                modes::initialize::Precondition::from_payload(payload)
                    .map(Precondition::Initialize)
            }
            modes::verify::MODE => {
                modes::verify::Precondition::from_payload(payload)
                    .map(Precondition::StarkVerify)
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Precondition::Initialize(p) => (modes::initialize::MODE, p.to_payload()),
            Precondition::StarkVerify(p) => (modes::verify::MODE, p.to_payload()),
        }
    }
}
