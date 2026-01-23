use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),

	// -- Rule Loading
	RuleFileNotFound(String),
	RuleParseError(String),
	InvalidRuleDefinition(String),

	// -- Evaluation
	ConditionEvaluationFailed(String),
	MissingCondition(String),

	// -- ONNX
	#[cfg(feature = "onnx")]
	OnnxModelLoadFailed(String),
	#[cfg(feature = "onnx")]
	OnnxInferenceFailed(String),

	// -- Externals
	#[from]
	Io(std::io::Error),
	#[from]
	TomlParse(toml::de::Error),
	#[from]
	Hel(hel::HelError),
	#[cfg(feature = "onnx")]
	#[from]
	TractOnnx(tract_onnx::prelude::TractError),
}

// region:    --- Custom

impl Error {
	pub fn custom_from_err(err: impl std::error::Error) -> Self {
		Self::Custom(err.to_string())
	}

	pub fn custom(val: impl Into<String>) -> Self {
		Self::Custom(val.into())
	}
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
