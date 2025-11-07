use zcash_primitives::extensions::transparent::{FromPayload, ToPayload};

use crate::transparent::stark_verify::{error::Error, modes};

/// The witness type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Witness {
    Initialize(modes::initialize::Witness),
    StarkVerify(modes::verify::Witness),
}

impl Witness {
    /// Convenience constructor for initialize witness values.
    pub fn initialize() -> Self {
        Witness::Initialize(modes::initialize::Witness)
    }

    /// Convenience constructor for stark_verify witness values.
    pub fn stark_verify(proof_data: Vec<u8>, with_pedersen: bool, proof_format: modes::verify::ProofFormat) -> Self {
        Witness::StarkVerify(modes::verify::Witness {
            with_pedersen,
            proof_format,
            proof_data,
        })
    }
}

impl TryFrom<(u32, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (modes::initialize::MODE, Witness::Initialize(w)) => Ok(Witness::Initialize(w)),
            (modes::verify::MODE, Witness::StarkVerify(w)) => Ok(Witness::StarkVerify(w)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            modes::initialize::MODE => {
                modes::initialize::Witness::from_payload(payload)
                    .map(Witness::Initialize)
            }
            modes::verify::MODE => {
                modes::verify::Witness::from_payload(payload)
                    .map(Witness::StarkVerify)
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Initialize(w) => (modes::initialize::MODE, w.to_payload()),
            Witness::StarkVerify(w) => (modes::verify::MODE, w.to_payload()),
        }
    }
}
