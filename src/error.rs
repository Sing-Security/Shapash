//! The crate's error type and result alias.
//!
//! One enum covers every failure a caller can meet: rule files that will not load, HEL
//! conditions that will not parse, and the I/O, TOML and HEL errors underneath them. The
//! `From` conversions let `?` carry any of them up, so a caller normally only names
//! [`Error`] in a signature and never a variant.

use derive_more::{Display, From};

/// The result type returned by this crate.
///
/// Shorthand for `core::result::Result<T, `[`Error`]`>`.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong loading or running rules.
///
/// [`Display`](std::fmt::Display) renders the message; [`Debug`](std::fmt::Debug) renders the
/// variant and its payload, so an error can be logged either way round.
#[derive(Debug, Display, From)]
pub enum Error {
    /// A caller-supplied message, for a failure this crate has no variant for.
    ///
    /// Built with [`Error::custom`] or [`Error::custom_from_err`], or converted from a
    /// `String`/`&str` with `?`. The message is passed through unchanged.
    #[from(String, &String, &str)]
    #[display("{_0}")]
    Custom(String),

    // -- Rule Loading
    /// A rule file, or the `.hel` condition file it names, could not be read.
    ///
    /// Carries the path and the underlying I/O error, already formatted.
    #[display("{_0}")]
    RuleFileNotFound(String),
    /// A rule's condition is not a valid HEL expression.
    ///
    /// Carries the rule id and HEL's own parse diagnostic, which includes the line and column.
    #[display("{_0}")]
    RuleParseError(String),
    /// A rule's definition is internally inconsistent — both `condition` and `condition_file`
    /// set, or neither.
    #[display("{_0}")]
    InvalidRuleDefinition(String),

    // -- Evaluation
    /// A rule has neither `condition` nor `condition_file`.
    #[display("{_0}")]
    MissingCondition(String),
    /// A condition could not be evaluated at all, as opposed to evaluating to false.
    ///
    /// A failing rule does not stop [`execute`](crate::HeuristicEngine::execute); the failure is
    /// recorded per rule in
    /// [`RuleEvaluationResult::Error`](crate::RuleEvaluationResult::Error). This variant is for
    /// a caller that surfaces evaluation failures as errors of its own.
    #[display("{_0}")]
    ConditionEvaluationFailed(String),

    // -- ONNX
    /// The ONNX model could not be read, optimized, or made runnable.
    #[cfg(feature = "onnx")]
    #[display("{_0}")]
    OnnxModelLoadFailed(String),
    /// The ONNX model loaded but running it failed — a shape mismatch, or an unusable output.
    #[cfg(feature = "onnx")]
    #[display("{_0}")]
    OnnxInferenceFailed(String),

    // -- Externals
    /// Reading a rule file or a condition file failed.
    #[from]
    #[display("I/O error: {_0}")]
    Io(std::io::Error),
    /// A `.rule` file is not valid TOML.
    #[from]
    #[display("rule file is not valid TOML: {_0}")]
    TomlParse(toml::de::Error),
    /// A HEL condition failed to parse or evaluate.
    #[from]
    #[display("HEL: {_0}")]
    Hel(hel::HelError),
    /// The ONNX runtime reported an error.
    #[cfg(feature = "onnx")]
    #[from]
    #[display("ONNX: {_0}")]
    TractOnnx(tract_onnx::prelude::TractError),
}

// region:    --- Custom

impl Error {
    /// Wrap any [`std::error::Error`] as [`Error::Custom`], keeping its message and dropping
    /// its type.
    ///
    /// For bridging an error from a crate this one has no variant for.
    pub fn custom_from_err(err: impl std::error::Error) -> Self {
        Self::Custom(err.to_string())
    }

    /// Build an [`Error::Custom`] with an ad-hoc message.
    pub fn custom(val: impl Into<String>) -> Self {
        Self::Custom(val.into())
    }
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
