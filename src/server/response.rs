//! This module contains the template for a response which is sent by the [`winvoice_server`]

mod debug;
mod hash;
mod into_response;
mod login;
mod logout;
mod partial_eq;
mod partial_ord;
mod version;

use axum::{http::StatusCode, Json};
pub use login::LoginResponse;
pub use logout::LogoutResponse;
pub use version::VersionResponse;

use crate::api::Code;

/// Implements [`IntoResponse`](axum::response::IntoResponse) for any `struct` with this structure:
///
/// ```rust,ignore
/// struct Foo(T); // where `T` implements `IntoResponse`
/// impl_into_response!(Foo);
/// ```
#[macro_export]
macro_rules! new_response {
	($Name:ident($Type:ty) $(: $($derive:ident),+)*) => {
		#[doc = concat!(" A [`", stringify!($Type), "`] [`Response`](crate::server::Response)")]
		$(#[derive($($derive),+)])*
		pub struct $Name($crate::server::Response<$Type>);

		impl $Name
		{
			/// Get the content of this response.
			#[allow(dead_code)]
			pub const fn content(&self) -> &$Type
			{
				self.0.content()
			}

			/// Get the status of this response.
			#[allow(dead_code)]
			pub const fn status(&self) -> ::axum::http::StatusCode
			{
				self.0.status()
			}
		}

		impl ::axum::response::IntoResponse for $Name
		{
			fn into_response(self) -> ::axum::response::Response
			{
				self.0.into_response()
			}
		}
	};
}

/// The response which the [`winvoice_server`] may issue.
#[derive(Clone, Copy, Default)]
pub struct Response<T>(StatusCode, Json<T>);

impl<T> Response<T>
{
	/// Get the content of this [`Response`]
	#[allow(dead_code)]
	pub const fn content(&self) -> &T
	{
		&self.1 .0
	}

	/// Create a new [`Response`]
	pub const fn new(status_code: StatusCode, content: T) -> Self
	{
		Self(status_code, Json(content))
	}

	/// Get the content of this [`Response`]
	#[allow(dead_code)]
	pub const fn status(&self) -> StatusCode
	{
		self.0
	}
}

impl<T> Response<T>
where
	T: AsRef<Code>,
{
	/// Create a new [`Response`]
	pub fn from(content: T) -> Self
	{
		Self((*content.as_ref()).into(), Json(content))
	}
}
