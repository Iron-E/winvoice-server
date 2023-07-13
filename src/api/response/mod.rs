//! This module contains all of the responses to an HTTP [request](super::request) which the
//! [`winvoice_server`](crate) may issue.

mod delete;
mod get;
mod login;
mod logout;
mod post;
mod version;

/// The response to [updating](winvoice_adapter::Updatable::update) some information.
#[allow(dead_code)]
pub type Patch = Delete;
pub use delete::Delete;
pub use get::Get;
pub use login::Login;
pub use logout::Logout;
pub use post::Post;
pub use version::Version;
