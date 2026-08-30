/// The error type used across this crate.
pub type Error = Box<dyn std::error::Error>;

/// Convenience [`Result`] alias parameterized by [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
