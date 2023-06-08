//! The `server` module functions to spawn an [`axum_server`] which communicates over TLS.

mod auth;
mod db_session_store;
mod response;
mod state;

use core::{marker::PhantomData, time::Duration};
use std::net::SocketAddr;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use auth::{AuthContext, DbUserStore, InitializableWithAuthorization, RequireAuthLayer, UserStore};
use axum::{
	error_handling::HandleErrorLayer,
	extract::{Extension, Json, State},
	headers::{authorization::Basic, Authorization},
	http::StatusCode,
	response::IntoResponse,
	routing,
	BoxError,
	Router,
	TypedHeader,
};
use axum_login::{
	axum_sessions::{async_session::SessionStore, SessionLayer},
	AuthLayer,
	SqlxStore,
};
use axum_server::tls_rustls::RustlsConfig;
use db_session_store::DbSessionStore;
pub use response::{LoginResponse, LogoutResponse, Response};
use sqlx::{Connection, Database, Executor, QueryBuilder, Transaction};
pub use state::ServerState;
use tower::{timeout, ServiceBuilder};
use tower_http::{compression::CompressionLayer, trace::TraceLayer};
use winvoice_adapter::{fmt::sql, Deletable, Initializable, Retrievable, Updatable};

use crate::{
	api::{
		r#match::MatchUser,
		request,
		response::Retrieve,
		schema::{columns::UserColumns, Adapter, User},
		Code,
		Status,
	},
	permissions::{Action, Object},
	DynResult,
};

/// Create routes which are able to be implemented generically.
macro_rules! route {
	($Entity:ident) => {
		routing::delete(|| async move { todo("Delete method not implemented") })
			.get(
				|Extension(user): Extension<User>,
				 State(state): State<ServerState<A::Db>>,
				 Json(request): Json<request::Retrieve<<A::$Entity as Retrievable>::Match>>| async move {
					state.has_permission(&user, Object::$Entity, Action::Retrieve).await.map_err(
						|status| {
							Response::from(Retrieve::<<A::$Entity as Retrievable>::Entity>::from(
								status,
							))
						},
					)?;

					A::$Entity::retrieve(state.pool(), request.into_condition()).await.map_or_else(
						|e| {
							Ok(Response::from(
								Retrieve::<<A::$Entity as Retrievable>::Entity>::from(
									Status::from(&e),
								),
							))
						},
						|vec| Err(Response::from(Retrieve::new(vec, Code::Success.into()))),
					)
				},
			)
			.patch(|| async move { todo("Update method not implemented") })
	};
}

/// A Winvoice server.
#[derive(Clone, Debug)]
pub struct Server<A>
{
	/// The [`SocketAddr`] that self server is bound to.
	address: SocketAddr,

	phantom: PhantomData<A>,

	/// The TLS configuration.
	tls: RustlsConfig,
}

impl<A> Server<A>
where
	A: 'static + Adapter + InitializableWithAuthorization,
	<A::Db as Database>::Connection: core::fmt::Debug,
	<<A::Db as Database>::Connection as Connection>::Options: Clone,
	A::User: Default,
	DbSessionStore<A::Db>: Initializable<Db = A::Db> + SessionStore,
	DbUserStore<A::Db>: UserStore,
	for<'args> QueryBuilder<'args, A::Db>: From<A::User>,
	for<'connection> &'connection mut <A::Db as Database>::Connection:
		Executor<'connection, Database = A::Db>,
	for<'connection> &'connection mut Transaction<'connection, A::Db>:
		Executor<'connection, Database = A::Db>,
{
	/// Create a new [`Server`]
	pub const fn new(address: SocketAddr, tls: RustlsConfig) -> Self
	{
		Self { address, phantom: PhantomData, tls }
	}

	/// Create an [`Router`] based on the `connect_options`.
	///
	/// Operations `timeout`, if specified.
	pub async fn serve(
		self,
		cookie_domain: Option<String>,
		cookie_secret: Vec<u8>,
		state: ServerState<A::Db>,
		session_ttl: Duration,
		timeout: Option<Duration>,
	) -> DynResult<()>
	{
		let router =
			Self::router(cookie_domain, cookie_secret, state, session_ttl, timeout).await?;
		axum_server::bind_rustls(self.address, self.tls).serve(router.into_make_service()).await?;
		Ok(())
	}

	/// Create the [`Router`] that will be used by the [`Server`].
	async fn router(
		cookie_domain: Option<String>,
		cookie_secret: Vec<u8>,
		state: ServerState<A::Db>,
		session_ttl: Duration,
		timeout: Option<Duration>,
	) -> DynResult<Router>
	{
		let session_store = DbSessionStore::new(state.pool().clone());
		futures::try_join!(A::init_with_auth(state.pool()), session_store.init())?;

		let mut router = Router::new();
		if let Some(t) = timeout
		{
			router = router.layer(
				ServiceBuilder::new()
					.layer(HandleErrorLayer::new(|err: BoxError| async move {
						match err.is::<timeout::error::Elapsed>()
						{
							#[rustfmt::skip]
							true => (StatusCode::REQUEST_TIMEOUT, "Request took too long".to_owned()),
							false => (
								StatusCode::INTERNAL_SERVER_ERROR,
								format!("Unhandled internal error: {err}"),
							),
						}
					}))
					.timeout(t),
			);
		}

		Ok(router
			.layer(CompressionLayer::new())
			.layer(AuthLayer::new(
				SqlxStore::<_, User>::new(state.pool().clone()).with_query({
					let mut query = QueryBuilder::<A::Db>::from(A::User::default());
					query.push(sql::WHERE).push(UserColumns::default().id).push(" = $1");
					query.into_sql()
				}),
				&cookie_secret,
			))
			.layer({
				let mut layer = SessionLayer::new(session_store, &cookie_secret)
					.with_session_ttl(session_ttl.into());

				if let Some(s) = cookie_domain
				{
					layer = layer.with_cookie_domain(s);
				}

				layer
			})
			.layer(TraceLayer::new_for_http())
			.route("/contact", route!(Contact).post(|| async move { todo("contact create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/employee", route!(Employee).post(|| async move { todo("employee create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/expense", route!(Expenses).post(|| async move { todo("expense create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/job", route!(Job).post(|| async move { todo("job create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/location", route!(Location).post(|| async move { todo("location create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/login", routing::get(Self::handle_get_login))
			.route("/logout", routing::get(Self::handle_get_logout))
			.route(
				"/organization",
				route!(Organization).post(|| async move { todo("organization create") }),
			)
			.route_layer(RequireAuthLayer::login())
			.route("/role", route!(Role).post(|| async move { todo("role create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/timesheet", route!(Timesheet).post(|| async move { todo("timesheet create") }))
			.route_layer(RequireAuthLayer::login())
			.route("/user", route!(User).post(|| async move { todo("user create") }))
			.route_layer(RequireAuthLayer::login())
			.with_state(state))
	}

	/// The [handler](axum::Handler) for [GET](routing::get) on "/login".
	async fn handle_get_login(
		mut auth: AuthContext<A::Db>,
		State(state): State<ServerState<A::Db>>,
		TypedHeader(credentials): TypedHeader<Authorization<Basic>>,
	) -> impl IntoResponse
	{
		let user = match A::User::retrieve(state.pool(), MatchUser {
			username: credentials.username().to_owned().into(),
			..Default::default()
		})
		.await
		.map(|mut v| v.pop())
		{
			Ok(Some(u)) => u,
			Ok(None) => return Err(LoginResponse::invalid_credentials(None)),
			Err(e) => return Err(LoginResponse::from(e)),
		};

		PasswordHash::new(user.password())
			.and_then(|hash| Argon2::default().verify_password(user.password().as_bytes(), &hash))
			.map_err(LoginResponse::from)?;

		auth.login(&user).await.map(|_| LoginResponse::from(Code::Success)).map_err(|e| {
			let code = Code::LoginError;
			LoginResponse::new(code.into(), Status::new(code, e.to_string()))
		})
	}

	/// The [handler](axum::Handler) for [GET](routing::get) on "/logout".
	async fn handle_get_logout(mut auth: AuthContext<A::Db>) -> impl IntoResponse
	{
		auth.logout().await;
		LogoutResponse::from(Code::Success)
	}
}

const fn todo(msg: &'static str) -> (StatusCode, &'static str)
{
	(StatusCode::NOT_IMPLEMENTED, msg)
}
