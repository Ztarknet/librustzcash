use std::fmt;

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
    /// Verification error indicating that OS program hashes don't match across input, output, and proof.
    OsProgramHashMismatch,
    /// Verification error indicating that bootloader program hashes don't match across input, output, and proof.
    BootloaderHashMismatch,
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
            Error::OsProgramHashMismatch => write!(f, "OS program hash mismatch between input, output, and proof"),
            Error::BootloaderHashMismatch => write!(f, "Bootloader program hash mismatch between input, output, and proof"),
        }
    }
}
