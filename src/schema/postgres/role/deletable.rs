//! A [`Deletable`] implementation for [`PgRole`]

use sqlx::{Executor, Postgres, Result};
use winvoice_adapter::Deletable;
use winvoice_adapter_postgres::{fmt::PgUuid, PgSchema};

use super::PgRole;
use crate::schema::{columns::RoleColumns, Role};

#[async_trait::async_trait]
impl Deletable for PgRole
{
	type Db = Postgres;
	type Entity = Role;

	#[tracing::instrument(level = "trace", skip_all, err)]
	async fn delete<'entity, Conn, Iter>(connection: &Conn, entities: Iter) -> Result<()>
	where
		Self::Entity: 'entity,
		Iter: Iterator<Item = &'entity Self::Entity> + Send,
		for<'con> &'con Conn: Executor<'con, Database = Self::Db>,
	{
		fn mapper(o: &Role) -> PgUuid
		{
			PgUuid::from(o.id())
		}

		// TODO: use `for<'a> |e: &'a Role| e.id`
		PgSchema::delete::<_, _, RoleColumns>(connection, entities.map(mapper)).await
	}
}
