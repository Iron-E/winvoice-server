//! Contains a request to [retrieve](winvoice_adapter::Retrievable)

use serde::{Deserialize, Serialize};

/// The request to [retrieve](winvoice_adapter::Retrievable::retrieve) some information.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Post<Match>
{
	/// See [`Retrieve::condition`]
	condition: Match,
}

impl<Match> Post<Match>
{
	/// Create a new POST request body.
	#[allow(dead_code)]
	pub const fn new(condition: Match) -> Self
	{
		Self { condition }
	}

	/// The condition used to filter which entities should be retrieved.
	///
	/// # See also
	///
	/// * [`winvoice_match`]
	/// * [`winvoice_server::api::match`](crate::match)
	#[allow(dead_code)]
	pub const fn condition(&self) -> &Match
	{
		&self.condition
	}

	/// HACK: can't be an `Into` impl because rust-lang/rust#31844
	///
	/// # See also
	///
	/// * [`Retrieve::condition`]
	#[allow(clippy::missing_const_for_fn)] // destructor cannot be evaluated at compile-time
	pub fn into_condition(self) -> Match
	{
		self.condition
	}
}
