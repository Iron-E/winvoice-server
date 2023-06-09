//! This module contains data used in reporting the success/failure of an operation on the server.

mod as_ref;
mod code;

#[cfg(feature = "bin")]
mod from;

pub use code::Code;
use serde::{Deserialize, Serialize};

/// The status of an operation.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Status
{
	/// The status code which has resulted from the operation.
	code: Code,

	/// The specific message attached to the status.
	message: String,
}

impl Status
{
	/// The status code which has resulted from the operation.
	pub const fn code(&self) -> Code
	{
		self.code
	}

	/// The specific message attached to the status.
	#[allow(dead_code)]
	pub fn message(&self) -> &str
	{
		self.message.as_ref()
	}

	/// Create a new [`Status`].
	pub const fn new(code: Code, message: String) -> Self
	{
		Self { code, message }
	}
}
