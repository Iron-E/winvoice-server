//! This module contains the response for a [retrieve](winvoice_adapter::Retrievable) operation.

use serde::{Deserialize, Serialize};

use crate::api::Status;

/// The logout request response.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Retrieve<T>
{
	/// The entities in the database which [match](winvoice_match)ed the
	/// [request](crate::api::request::Retrieve) parameters.
	entities: Vec<T>,

	/// The [`Status`] of this request.
	status: Status,
}

impl<T> Retrieve<T>
{
	/// Create a new [`Retrieve`] response.
	pub const fn new(entities: Vec<T>, status: Status) -> Self
	{
		Self { entities, status }
	}

	pub fn entities(&self) -> &[T]
	{
		self.entities.as_ref()
	}

	/// The [`Status`] of the logout request.
	pub const fn status(&self) -> &Status
	{
		&self.status
	}
}
