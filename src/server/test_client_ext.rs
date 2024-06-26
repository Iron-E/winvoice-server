//! Contains [extensions](TestClientExt) for [`TestClient`].

use core::{
	fmt::Debug,
	hash::Hash,
	marker::{Send, Sync},
};
use std::{collections::HashSet, sync::OnceLock};

use axum::http::header;
use axum_login::axum_sessions::async_session::base64;
use axum_test_helper::{RequestBuilder, TestClient};
use pretty_assertions::{assert_eq, assert_ne};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::Pool;
use winvoice_adapter::{Deletable, Retrievable};

use super::response::{LoginResponse, LogoutResponse};
use crate::{
	api::{
		self,
		request,
		response::{Delete, Login, Logout, Patch, Post, Put},
		routes,
		Code,
		Status,
	},
	schema::User,
	server::response::Response,
};

/// Post the default version requirement for tests.
fn version_req() -> &'static str
{
	static VERSION_REQ: OnceLock<String> = OnceLock::new();
	VERSION_REQ.get_or_init(|| format!("={}", api::version()))
}

/// Controls what HTTP method is being tested by [`TestClientExt::test_other_success`] /
/// [`TestClientExt::test_other_unauthorized`].
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Method
{
	/// The `DELETE` method.
	Delete,

	/// The `PATCH` method.
	Patch,
}

/// Extensions for [`TestClient`].
#[async_trait::async_trait]
pub trait TestClientExt
{
	/// Make a DELETE [`RequestBuilder`] on the given `route`.
	fn delete_builder(&self, route: &str) -> RequestBuilder;

	/// Make a GET [`RequestBuilder`] on the given `route`.
	fn get_builder(&self, route: &str) -> RequestBuilder;

	/// Make a POST [`RequestBuilder`] on the given `route`.
	fn post_builder(&self, route: &str) -> RequestBuilder;

	/// Log in a [`User`](crate::schema::User) into the [`TestClient`].
	async fn login(&self, user: &User, password: &str);

	/// Log out a [`User`](crate::schema::User) into the [`TestClient`].
	async fn logout(&self);

	/// Make a PATCH [`RequestBuilder`] on the given `route`.
	fn patch_builder(&self, route: &str) -> RequestBuilder;

	/// Make a PUT [`RequestBuilder`] on the given `route`.
	fn put_builder(&self, route: &str) -> RequestBuilder;

	/// assert logged in user POST with permissions is accepted
	async fn test_get_success<'ent, M, E, Iter>(
		&self,
		route: &str,
		user: &User,
		password: &str,
		condition: M,
		entities: Iter,
		code: Option<Code>,
	) where
		E: 'ent + Clone + Debug + DeserializeOwned + Eq + Hash + PartialEq + Send + Serialize,
		Iter: Debug + Iterator<Item = &'ent E> + Send,
		M: Debug + Serialize + Send + Sync;

	/// assert logged in user POST with permissions is rejected
	async fn test_get_unauthorized<M>(&self, route: &str, user: &User, password: &str)
	where
		M: Debug + Default + Serialize + Send + Sync;

	/// assert logged in user DELETE with permissions is accepted
	#[allow(clippy::too_many_arguments)]
	async fn test_other_success<A>(
		&self,
		method: Method,
		pool: &Pool<<A as Deletable>::Db>,
		route: &str,
		user: &User,
		password: &str,
		entities: Vec<(<A as Deletable>::Entity, bool)>,
		code: Option<Code>,
	) where
		A: Deletable + Retrievable<Db = <A as Deletable>::Db, Entity = <A as Deletable>::Entity>,
		<A as Deletable>::Entity: Clone + Debug + PartialEq + Send + Serialize + Sync,
		A::Match: Debug + From<<A as Retrievable>::Entity> + Send;

	/// assert logged in user DELETE with permissions is rejected
	async fn test_other_unauthorized(&self, method: Method, route: &str, user: &User, password: &str);

	/// assert logged in user PUT with permissions is accepted
	async fn test_post_success<R, A>(
		&self,
		pool: &Pool<R::Db>,
		route: &str,
		user: &User,
		password: &str,
		args: A,
	) -> R::Entity
	where
		A: Debug + Send + Serialize + Sync,
		R: Retrievable,
		R::Entity: Clone + Debug + DeserializeOwned + PartialEq + Send,
		R::Match: Debug + From<R::Entity> + Send;

	/// assert logged in user PUT with permissions is rejected
	async fn test_post_unauthorized<A>(&self, route: &str, user: &User, password: &str, args: A)
	where
		A: Debug + Send + Serialize + Sync;
}

#[async_trait::async_trait]
impl TestClientExt for TestClient
{
	fn delete_builder(&self, route: &str) -> RequestBuilder
	{
		self.delete(route).header(api::HEADER, version_req())
	}

	fn get_builder(&self, route: &str) -> RequestBuilder
	{
		self.get(route).header(api::HEADER, version_req())
	}

	fn post_builder(&self, route: &str) -> RequestBuilder
	{
		self.post(route).header(api::HEADER, version_req())
	}

	#[tracing::instrument(skip(self))]
	async fn login(&self, user: &User, password: &str)
	{
		let response = self
			.post(routes::LOGIN)
			.header(api::HEADER, version_req())
			.header(
				header::AUTHORIZATION,
				format!("Basic {}", base64::encode(format!("{}:{password}", user.username()))),
			)
			.send()
			.await;

		let expected = LoginResponse::from(user.clone());
		assert_eq!(response.status(), expected.status());
		assert_eq!(&response.json::<Login>().await, expected.content());
	}

	#[tracing::instrument(skip(self))]
	async fn logout(&self)
	{
		let response = self.post(routes::LOGOUT).header(api::HEADER, version_req()).send().await;
		let expected = LogoutResponse::from(Code::Success);
		assert_eq!(response.status(), expected.status());
		assert_eq!(&response.json::<Logout>().await, expected.content());
	}

	fn patch_builder(&self, route: &str) -> RequestBuilder
	{
		self.patch(route).header(api::HEADER, version_req())
	}

	fn put_builder(&self, route: &str) -> RequestBuilder
	{
		self.put(route).header(api::HEADER, version_req())
	}

	#[tracing::instrument(skip(self))]
	async fn test_get_success<'ent, M, E, Iter>(
		&self,
		route: &str,
		user: &User,
		password: &str,
		condition: M,
		entities: Iter,
		code: Option<Code>,
	) where
		E: 'ent + Clone + Debug + DeserializeOwned + Eq + Hash + PartialEq + Send + Serialize,
		Iter: Debug + Iterator<Item = &'ent E> + Send,
		M: Debug + Serialize + Send + Sync,
	{
		// HACK: `tracing` doesn't work correctly with asyn cso I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let response = self.post_builder(route).json(&request::Post::new(condition)).send().await;

		let actual = Response::new(response.status(), response.json::<Post<E>>().await);
		let expected = Response::from(Post::<E>::new(
			entities.into_iter().cloned().collect(),
			code.unwrap_or(Code::Success).into(),
		));

		assert_eq!(
			actual.content().entities().iter().collect::<HashSet<_>>(),
			expected.content().entities().iter().collect::<HashSet<_>>()
		);
		assert_eq!(actual.content().status(), expected.content().status());
		assert_eq!(actual.status(), expected.status());
		self.logout().await;
	}

	#[tracing::instrument(skip(self))]
	async fn test_get_unauthorized<M>(&self, route: &str, user: &User, password: &str)
	where
		M: Debug + Default + Serialize + Send + Sync,
	{
		// HACK: `tracing` doesn't work correctly with asyn cso I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let response = self.post_builder(route).json(&request::Post::new(M::default())).send().await;

		let actual = Response::new(response.status(), response.json::<Post<()>>().await);
		let expected = Response::from(Post::<()>::from(Status::from(Code::Unauthorized)));

		assert_eq!(actual.status(), expected.status());
		assert_eq!(actual.content().entities(), expected.content().entities());
		assert_eq!(actual.content().status().code(), expected.content().status().code());
		self.logout().await;
	}

	/// assert logged in user DELETE with permissions is accepted
	#[tracing::instrument(skip(self, pool))]
	async fn test_other_success<A>(
		&self,
		method: Method,
		pool: &Pool<<A as Deletable>::Db>,
		route: &str,
		user: &User,
		password: &str,
		entities: Vec<(<A as Deletable>::Entity, bool)>,
		code: Option<Code>,
	) where
		A: Deletable + Retrievable<Db = <A as Deletable>::Db, Entity = <A as Deletable>::Entity>,
		<A as Deletable>::Entity: Clone + Debug + PartialEq + Send + Serialize + Sync,
		A::Match: Debug + From<<A as Retrievable>::Entity> + Send,
	{
		// HACK: `tracing` doesn't work correctly with async so I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let entities_destructured = entities.iter().map(|(e, _)| e.clone()).collect();
		let response = match method
		{
			Method::Delete => self.delete_builder(route).json(&request::Delete::new(entities_destructured)),
			Method::Patch => self.patch_builder(route).json(&request::Patch::new(entities_destructured)),
		}
		.send()
		.await;

		let actual = Response::new(response.status(), response.json::<Delete>().await);
		let expected = Response::from(match method
		{
			Method::Delete => Delete::new,
			Method::Patch => Patch::new,
		}(code.unwrap_or(Code::Success).into()));

		assert_eq!(actual, expected);
		if code != Some(Code::Unauthorized)
		{
			for (entity, expected) in entities
			{
				let retrieved = A::retrieve(pool, A::Match::from(entity.clone())).await.unwrap();
				match method
				{
					Method::Delete => assert!(retrieved.is_empty() == expected),
					Method::Patch if expected =>
					{
						tracing::debug!(parent: None, "checking if {retrieved:#?} is {entity:#?}");
						assert_eq!(retrieved.get(0), Some(&entity))
					},
					Method::Patch =>
					{
						tracing::debug!(parent: None, "checking if {retrieved:#?} is NOT {entity:#?}");
						assert_ne!(retrieved.get(0), Some(&entity))
					},
				}
			}
		}

		self.logout().await;
	}

	/// assert logged in user DELETE with permissions is rejected
	#[tracing::instrument(skip(self))]
	async fn test_other_unauthorized(&self, method: Method, route: &str, user: &User, password: &str)
	{
		// HACK: `tracing` doesn't work correctly with async so I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let response = match method
		{
			Method::Delete => self.delete_builder(route).json(&request::Delete::<()>::new(Default::default())),
			Method::Patch => self.patch_builder(route).json(&request::Patch::<()>::new(Default::default())),
		}
		.send()
		.await;

		let actual = Response::new(response.status(), response.json::<Delete>().await);
		let expected = Response::from(match method
		{
			Method::Delete => Delete::new,
			Method::Patch => Patch::new,
		}(Code::Unauthorized.into()));

		assert_eq!(actual.status(), expected.status());
		assert_eq!(actual.content().status().code(), expected.content().status().code());
		self.logout().await;
	}

	#[tracing::instrument(skip(self))]
	async fn test_post_success<R, A>(
		&self,
		pool: &Pool<R::Db>,
		route: &str,
		user: &User,
		password: &str,
		args: A,
	) -> R::Entity
	where
		A: Debug + Send + Serialize + Sync,
		R: Retrievable,
		R::Entity: Clone + Debug + DeserializeOwned + PartialEq + Send,
		R::Match: Debug + From<R::Entity> + Send,
	{
		// HACK: `tracing` doesn't work correctly with async so I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let response = self.put_builder(route).json(&request::Put::new(args)).send().await;

		let actual = Response::new(response.status(), response.json::<Put<R::Entity>>().await);
		tracing::debug!("\n\nReceived {actual:#?}\n\n");
		let expected = {
			let entity = actual.content().entity().unwrap().clone();
			let row = R::retrieve(pool, R::Match::from(entity)).await.map(|mut v| v.remove(0)).unwrap();
			Response::from(Put::new(row.into(), Code::Success.into()))
		};

		assert_eq!(actual, expected);
		self.logout().await;

		actual.into_content().into_entity().unwrap()
	}

	#[tracing::instrument(skip(self))]
	async fn test_post_unauthorized<A>(&self, route: &str, user: &User, password: &str, args: A)
	where
		A: Debug + Send + Serialize + Sync,
	{
		// HACK: `tracing` doesn't work correctly with async so I have to annotate this function
		// like       this or else this function's span is skipped.
		tracing::trace!(parent: None, "\n");
		tracing::trace!("\n");

		self.login(user, password).await;
		let response = self.put_builder(route).json(&request::Put::new(args)).send().await;

		let actual = Response::new(response.status(), response.json::<Put<()>>().await);
		let expected = Response::from(Put::new(None, Code::Unauthorized.into()));

		assert_eq!(actual.status(), expected.status());
		assert_eq!(actual.content().entity(), expected.content().entity());
		assert_eq!(actual.content().status().code(), expected.content().status().code());
		self.logout().await;
	}
}
