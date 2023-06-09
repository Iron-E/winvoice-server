//! Contains an [`Updatable`] implementation for [`PgRole`]

use sqlx::{Postgres, Result, Transaction};
use winvoice_adapter::Updatable;
use winvoice_adapter_postgres::PgSchema;

use super::PgRole;
use crate::schema::{columns::RoleColumns, Role};

#[async_trait::async_trait]
impl Updatable for PgRole
{
	type Db = Postgres;
	type Entity = Role;

	#[tracing::instrument(level = "trace", skip_all, err)]
	async fn update<'entity, Iter>(connection: &mut Transaction<Self::Db>, entities: Iter) -> Result<()>
	where
		Self::Entity: 'entity,
		Iter: Clone + Iterator<Item = &'entity Self::Entity> + Send,
	{
		let mut peekable_entities = entities.clone().peekable();

		// There is nothing to do.
		if peekable_entities.peek().is_none()
		{
			return Ok(());
		}

		PgSchema::update(connection, RoleColumns::default(), |query| {
			query.push_values(peekable_entities, |mut q, e| {
				q.push_bind(e.id()).push_bind(e.name()).push_bind(e.password_ttl());
			});
		})
		.await
	}
}
