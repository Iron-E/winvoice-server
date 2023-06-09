//! This module contains all of the responses to an HTTP [request](super::request) which the
//! [`winvoice_server`](crate) may issue.

mod login;
mod logout;
mod retrieve;
mod version;

pub use login::Login;
pub use logout::Logout;
pub use retrieve::Retrieve;
pub use version::Version;
