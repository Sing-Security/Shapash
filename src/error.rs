use std::num::ParseIntError;

use derive_more::{Display, From};
use tract_onnx::tract_core::ndarray::ShapeError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
#[display("{self:?}")]
pub enum Error {
	#[from(String, &String, &str)]
	Custom(String),

	#[from]
	Anyhow(anyhow::Error),
	#[from]
	Toml(toml::de::Error),
	#[from]
	ParseInt(ParseIntError),
	#[from]
	ShapeError(ShapeError),
	// -- Externals
	#[from]
	Io(std::io::Error),
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
