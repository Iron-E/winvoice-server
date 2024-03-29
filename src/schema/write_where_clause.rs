//! Contains extensions to adapter implementations of [`WriteWhereClause`].

use core::fmt::Display;

use sqlx::QueryBuilder;
use winvoice_adapter::{WriteContext, WriteWhereClause};

use crate::{
	r#match::{MatchRole, MatchUser},
	schema::columns::{RoleColumns, UserColumns},
};

#[cfg(feature = "postgres")]
mod postgres
{
	use sqlx::Postgres;
	use winvoice_adapter_postgres::{
		fmt::{PgInterval, PgTimestampTz, PgUuid},
		PgSchema,
	};

	#[allow(clippy::wildcard_imports)]
	use super::*;

	impl WriteWhereClause<Postgres, &MatchRole> for PgSchema
	{
		fn write_where_clause<Ident>(
			context: WriteContext,
			ident: Ident,
			match_condition: &MatchRole,
			query: &mut QueryBuilder<Postgres>,
		) -> WriteContext
		where
			Ident: Copy + Display,
		{
			let columns = RoleColumns::default().scope(ident);

			Self::write_where_clause(
				Self::write_where_clause(
					Self::write_where_clause(context, columns.id, &match_condition.id.map_copied(PgUuid::from), query),
					columns.name,
					&match_condition.name,
					query,
				),
				columns.password_ttl,
				&match_condition.password_ttl.map_ref(|m| m.map_copied(PgInterval::from)),
				query,
			)
		}
	}

	impl WriteWhereClause<Postgres, &MatchUser> for PgSchema
	{
		fn write_where_clause<Ident>(
			context: WriteContext,
			ident: Ident,
			match_condition: &MatchUser,
			query: &mut QueryBuilder<Postgres>,
		) -> WriteContext
		where
			Ident: Copy + Display,
		{
			let columns = UserColumns::default().scope(ident);

			Self::write_where_clause(
				Self::write_where_clause(
					Self::write_where_clause(
						Self::write_where_clause(
							context,
							columns.id,
							&match_condition.id.map_copied(PgUuid::from),
							query,
						),
						columns.password,
						&match_condition.password,
						query,
					),
					columns.password_set,
					&match_condition.password_set.map_copied(PgTimestampTz::from),
					query,
				),
				columns.username,
				&match_condition.username,
				query,
			)
		}
	}
}
