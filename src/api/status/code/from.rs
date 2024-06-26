//! Implementations of [`From`] for [`Code`].

use argon2::password_hash::Error as HashError;
use axum::http::StatusCode;
use casbin::Error as CasbinError;
use money2::Error as MoneyError;
use sqlx::Error as SqlxError;
use winvoice_schema::{chrono::OutOfRangeError, IncrementError};

use super::Code;

impl From<Code> for u8
{
	fn from(code: Code) -> Self
	{
		code as Self
	}
}

impl From<Code> for StatusCode
{
	fn from(code: Code) -> Self
	{
		match code
		{
			Code::ApiVersionMismatch => Self::GONE,
			Code::InvalidCredentials | Code::PasswordExpired => Self::UNPROCESSABLE_ENTITY,
			Code::Success | Code::SuccessForPermissions => Self::OK,
			Code::Unauthorized => Self::FORBIDDEN,

			Code::ApiVersionHeaderMissing | Code::EncodingError => Self::BAD_REQUEST,

			Code::BadArguments |
			Code::CryptError |
			Code::Database |
			Code::ExchangeError |
			Code::LoginError |
			Code::Other |
			Code::PermissionsError |
			Code::SqlError => Self::INTERNAL_SERVER_ERROR,
		}
	}
}

impl From<&CasbinError> for Code
{
	fn from(error: &CasbinError) -> Self
	{
		match error
		{
			CasbinError::RequestError(_) => Self::PermissionsError,

			CasbinError::AdapterError(_) |
			CasbinError::IoError(_) |
			CasbinError::ModelError(_) |
			CasbinError::PolicyError(_) |
			CasbinError::RbacError(_) |
			CasbinError::RhaiError(_) |
			CasbinError::RhaiParseError(_) => Self::Other,
		}
	}
}

impl From<&HashError> for Code
{
	fn from(error: &HashError) -> Self
	{
		match error
		{
			HashError::B64Encoding(_) => Self::EncodingError,
			HashError::Crypto => Self::CryptError,
			HashError::Password => Self::InvalidCredentials,
			_ => Self::Other,
		}
	}
}

impl From<&IncrementError> for Code
{
	fn from(error: &IncrementError) -> Self
	{
		match error
		{
			IncrementError::OutOfRange(e) => e.into(),
			IncrementError::Rounding(_) => Self::EncodingError,
		}
	}
}

impl From<&MoneyError> for Code
{
	fn from(_: &MoneyError) -> Self
	{
		Self::ExchangeError
	}
}

impl From<&OutOfRangeError> for Code
{
	fn from(_: &OutOfRangeError) -> Self
	{
		Self::EncodingError
	}
}

impl From<&SqlxError> for Code
{
	fn from(error: &SqlxError) -> Self
	{
		match error
		{
			SqlxError::Configuration(_) => Self::BadArguments,

			SqlxError::ColumnDecode { .. } |
			SqlxError::ColumnIndexOutOfBounds { .. } |
			SqlxError::ColumnNotFound(_) |
			SqlxError::Decode(_) |
			SqlxError::RowNotFound |
			SqlxError::TypeNotFound { .. } => Self::SqlError,

			SqlxError::Io(_) |
			SqlxError::PoolClosed |
			SqlxError::PoolTimedOut |
			SqlxError::Protocol(_) |
			SqlxError::Tls(_) => Self::Database,

			_ => Self::Other,
		}
	}
}
