/// This trait defines the context information that the stark_verify extension
/// requires from a consensus node integrating this extension.
///
/// This context type provides accessors to information relevant to a single
/// transaction being validated by the extension.
pub trait Context {
    /// List of all TZE outputs in the transaction being validated by the extension.
    fn tx_tze_outputs(&self) -> &[zcash_primitives::transaction::components::tze::TzeOut];
}
