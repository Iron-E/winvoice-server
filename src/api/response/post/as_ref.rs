//! Implementations for [`AsRef`] for [`Retrieve`]

use super::Post;
use crate::api::Code;

impl<T> AsRef<Code> for Post<T>
{
	fn as_ref(&self) -> &Code
	{
		self.status.as_ref()
	}
}
