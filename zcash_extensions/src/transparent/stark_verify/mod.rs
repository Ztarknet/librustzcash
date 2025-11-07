//! STARK proof verification TZE implementation.
//!
//! This extension enables verification of STARK proofs within Zcash transactions.
//! The extension validates STARK proofs embedded in transaction witnesses against
//! verification keys and public inputs specified in preconditions.
//!
//! For now, this is a minimal implementation that always succeeds, providing
//! the structural foundation for proper STARK verification.

// Module declarations
pub mod builder;
pub mod context;
pub mod error;
pub mod modes;
pub mod precondition;
pub mod program;
pub mod witness;

#[cfg(test)]
mod tests;

// Public re-exports
pub use builder::{StarkVerifyBuilder, StarkVerifyBuildError};
pub use context::Context;
pub use error::Error;
pub use precondition::Precondition;
pub use program::Program;
pub use witness::Witness;

// Re-export mode-specific modules for public access
pub use modes::initialize;
pub use modes::verify as stark_verify;
