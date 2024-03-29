//! This module contains strongly-typed versions of all JSON information sent via the
//! server.

pub mod request;
pub mod response;
pub mod routes;
mod status;

use std::sync::OnceLock;

use semver::{BuildMetadata, Prerelease, Version};
pub use status::{Code, Status};

/// The header which is used to advertise the semantic version that the client accepts.
pub const HEADER: &str = "api-version";

/// The current API version.
static VERSION: OnceLock<Version> = OnceLock::new();

/// The current API version.
pub fn version() -> &'static Version
{
	VERSION.get_or_init(|| Version {
		build: BuildMetadata::EMPTY,
		major: 0,
		minor: 5,
		patch: 1,
		pre: Prerelease::EMPTY,
	})
}
