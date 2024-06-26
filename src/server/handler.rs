mod reason;

use core::{marker::PhantomData, time::Duration};
use std::collections::{BTreeSet, HashMap, HashSet};

use argon2::{password_hash::Error as HashError, Argon2, PasswordHash, PasswordVerifier};
use axum::{
	extract::State,
	headers::{authorization::Basic, Authorization},
	http::StatusCode,
	routing::{self, MethodRouter},
	Extension,
	Json,
	TypedHeader,
};
use futures::{stream, TryFutureExt, TryStreamExt};
use humantime_serde::Serde;
use money2::{Exchange, HistoricalExchangeRates};
use reason::Reason;
use sqlx::{Database, Executor, Pool};
use tracing::Instrument;
use winvoice_adapter::{
	schema::{
		ContactAdapter,
		DepartmentAdapter,
		EmployeeAdapter,
		ExpensesAdapter,
		JobAdapter,
		LocationAdapter,
		OrganizationAdapter,
		TimesheetAdapter,
	},
	Deletable,
	Retrievable,
	Updatable,
};
use winvoice_export::Format;
use winvoice_match::{Match, MatchDepartment, MatchEmployee, MatchExpense, MatchJob, MatchOption, MatchTimesheet};
use winvoice_schema::{
	chrono::{DateTime, Utc},
	ContactKind,
	Currency,
	Department,
	Employee,
	Expense,
	Id,
	Invoice,
	Job,
	Location,
	Money,
	Organization,
	Timesheet,
};

use super::{
	auth::{AuthContext, DbUserStore, UserStore},
	response::{
		DeleteResponse,
		ExportResponse,
		LoginResponse,
		LogoutResponse,
		PatchResponse,
		Response,
		ResponseResult,
		WhoAmIResponse,
	},
	ServerState,
};
use crate::{
	api::{
		request,
		response::{Post, Put},
		Code,
		Status,
	},
	bool_ext::BoolExt,
	permissions::{Action, Object},
	r#match::MatchUser,
	schema::{Adapter, Role, RoleAdapter, User, UserAdapter},
	twin_result::TwinResult,
	ResultExt,
};
/// Map `result` of creating some enti`T`y into a [`ResponseResult`].
fn create<T>(on_success: Code, result: sqlx::Result<T>) -> ResponseResult<Put<T>>
{
	result.map_all(
		|t| Response::from(Put::new(t.into(), on_success.into())),
		|e| Response::from(Put::from(Status::from(&e))),
	)
}

/// [Retrieve](Retrievable::retrieve) using `R`, and map the result into a [`ResponseResult`].
async fn delete<D>(pool: &Pool<D::Db>, entities: Vec<D::Entity>, on_success: Code) -> TwinResult<DeleteResponse>
where
	D: Deletable,
	D::Entity: Sync,
	for<'con> &'con mut <D::Db as Database>::Connection: Executor<'con, Database = D::Db>,
{
	D::delete(pool, entities.iter()).await.map_all(|_| DeleteResponse::from(on_success), DeleteResponse::from)
}

/// [Retrieve](Retrievable::retrieve) using `R`, and map the result into a [`ResponseResult`].
async fn retrieve<R>(
	pool: &Pool<R::Db>,
	condition: R::Match,
	on_success: Code,
) -> ResponseResult<Post<<R as Retrievable>::Entity>>
where
	R: Retrievable,
{
	R::retrieve(pool, condition).await.map_all(
		|vec| Response::from(Post::new(vec, on_success.into())),
		|e| Response::from(Post::from(Status::from(&e))),
	)
}

/// [Retrieve](Retrievable::retrieve) using `R`, and map the result into a [`ResponseResult`].
async fn update<U>(pool: &Pool<U::Db>, entities: Vec<U::Entity>, on_success: Code) -> TwinResult<PatchResponse>
where
	U: Updatable,
	U::Entity: Sync,
{
	let mut tx = pool.begin().await.map_err(PatchResponse::from)?;
	U::update(&mut tx, entities.iter()).await.map_err(PatchResponse::from)?;
	tx.commit().await.map_all(|_| PatchResponse::from(on_success), PatchResponse::from)
}

/// Return a [`ResponseResult`] for when a [`User`] tries to POST something, but they *effectively*
/// have no permissions (rather than outright having no permissions).
#[allow(clippy::unnecessary_wraps)]
fn no_effective_perms<R>(action: Action, object: Object, reason: Reason) -> ResponseResult<R>
where
	R: AsRef<Code> + From<Status>,
{
	Err(Response::from(R::from(Status::new(
		Code::Unauthorized,
		format!("This user has permission to {action} {object}, but {reason}"),
	))))
}

/// Create routes which are able to be implemented generically.
macro_rules! route {
	($Entity:ident, $Args:ty, $($param:ident$( = $map:expr)?),+) => {
		routing::delete(
				|Extension(user): Extension<User>,
				 State(state): State<ServerState<A::Db>>,
				 Json(request): Json<request::Delete<<A::$Entity as Deletable>::Entity>>| async move {
					state.enforce_permission(&user, Object::$Entity, Action::Delete).await?;
					delete::<A::$Entity>(state.pool(), request.into_entities(), Code::Success).await
				},
			)
			.post(
				|Extension(user): Extension<User>,
				 State(state): State<ServerState<A::Db>>,
				 Json(request): Json<request::Post<<A::$Entity as Retrievable>::Match>>| async move {
					state.enforce_permission(&user, Object::$Entity, Action::Retrieve).await?;
					retrieve::<A::$Entity>(state.pool(), request.into_condition(), Code::Success).await
				},
			)
			.patch(
				|Extension(user): Extension<User>,
				 State(state): State<ServerState<A::Db>>,
				 Json(request): Json<request::Patch<<A::$Entity as Deletable>::Entity>>| async move {
					state.enforce_permission(&user, Object::$Entity, Action::Update).await?;
					update::<A::$Entity>(state.pool(), request.into_entities(), Code::Success).await
				},
			)
			.put(
				|Extension(user): Extension<User>,
				 State(state): State<ServerState<A::Db>>,
				 Json(request): Json<request::Put<$Args>>| async move {
					state.enforce_permission(&user, Object::$Entity, Action::Create).await?;
					let ( $($param),+ ) = request.into_args();
					$($(let $param = $map;)*)+
					create(Code::Success, A::$Entity::create(state.pool(), $($param),+).await)
				},
			)
	};
}

/// A handler for [`routes`](crate::api::routes).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Handler<A>
{
	phantom: PhantomData<A>,
}

impl<A> Handler<A>
where
	A: Adapter,
	DbUserStore<A::Db>: UserStore,
	for<'con> &'con mut <A::Db as Database>::Connection: Executor<'con, Database = A::Db>,
{
	/// The handler for the [`routes::CONTACT`](crate::api::routes::CONTACT).
	pub fn contact(&self) -> MethodRouter<ServerState<A::Db>>
	{
		route!(Contact, (ContactKind, String), kind, name)
	}

	/// The handler for the [`routes::DEPARTMENT`](crate::api::routes::DEPARTMENT).
	pub fn department(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<Department>>| async move {
				const ACTION: Action = Action::Delete;
				let entities = request.into_entities();
				let code = match state.department_permissions(&user, ACTION).await?
				{
					Object::Department => Code::Success,

					p @ Object::AssignedDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::ResourceConstraint)
							.map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				delete::<A::Department>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchDepartment>>| async move {
				const ACTION: Action = Action::Retrieve;
				let mut condition = request.into_condition();
				let code = match state.department_permissions(&user, ACTION).await?
				{
					Object::Department => Code::Success,

					// HACK: no if-let guards…
					Object::AssignedDepartment if user.employee().is_some() =>
					{
						condition.id &= user.department().unwrap().id.into();
						Code::SuccessForPermissions
					},

					p @ Object::AssignedDepartment => return no_effective_perms(ACTION, p, Reason::NoDepartment),
					p => p.unreachable(),
				};

				retrieve::<A::Department>(state.pool(), condition, code).await
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<Department>>| async move {
				const ACTION: Action = Action::Update;
				let mut entities = request.into_entities();
				let code = match state.department_permissions(&user, ACTION).await?
				{
					Object::Department => Code::Success,

					// HACK: no if-let guards…
					Object::AssignedDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|d| d.id == id);
						Code::SuccessForPermissions
					},

					p @ Object::AssignedDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				update::<A::Department>(state.pool(), entities, code).await
			},
		)
		.put(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Put<String>>| async move {
				const ACTION: Action = Action::Create;
				let name = request.into_args();
				let code = match state.department_permissions(&user, ACTION).await?
				{
					Object::Department => Code::Success,

					p @ Object::AssignedDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::ResourceExists);
					},
					p => p.unreachable(),
				};

				create(code, A::Department::create(state.pool(), name).await)
			},
		)
	}

	/// The handler for the [`routes::EMPLOYEE`](crate::api::routes::EMPLOYEE).
	pub fn employee(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<Employee>>| async move {
				const ACTION: Action = Action::Delete;
				let mut entities = request.into_entities();
				let code = match state.employee_permissions(&user, ACTION).await?
				{
					Object::Employee => Code::Success,

					// HACK: no if-let guards…
					Object::EmployeeInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|e| e.department.id == id);
						Code::SuccessForPermissions
					},

					Object::EmployeeSelf =>
					{
						let id = user.employee().unwrap().id;
						entities.retain(|e| e.id == id);
						Code::SuccessForPermissions
					},

					p @ Object::EmployeeInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into)
					},

					p => p.unreachable(),
				};

				delete::<A::Employee>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchEmployee>>| async move {
				const ACTION: Action = Action::Retrieve;
				let mut condition = request.into_condition();
				let code = match state.employee_permissions(&user, ACTION).await?
				{
					Object::Employee => Code::Success,

					// HACK: no if-let guards…
					Object::EmployeeInDepartment if user.employee().is_some() =>
					{
						condition.department.id &= user.department().unwrap().id.into();
						Code::SuccessForPermissions
					},

					// HACK: no if-let guards…
					Object::EmployeeSelf if user.employee().is_some() =>
					{
						condition.id &= user.employee().unwrap().id.into();
						Code::SuccessForPermissions
					},

					p @ Object::EmployeeInDepartment => return no_effective_perms(ACTION, p, Reason::NoDepartment),
					p @ Object::EmployeeSelf =>
					{
						return no_effective_perms(ACTION, p, Reason::NoEmployee);
					},

					p => p.unreachable(),
				};

				retrieve::<A::Employee>(state.pool(), condition, code).await
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<Employee>>| async move {
				const ACTION: Action = Action::Update;
				let mut entities = request.into_entities();
				let code = match state.employee_permissions(&user, ACTION).await?
				{
					Object::Employee => Code::Success,

					// HACK: no if-let guards…
					Object::EmployeeInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|e| e.department.id == id);
						Code::SuccessForPermissions
					},

					// HACK: no if-let guards…
					Object::EmployeeSelf if user.employee().is_some() =>
					{
						let id = user.employee().unwrap().id;
						entities.retain(|e| e.id == id);
						Code::SuccessForPermissions
					},

					p @ Object::EmployeeInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into)
					},

					p @ Object::EmployeeSelf =>
					{
						return no_effective_perms(ACTION, p, Reason::NoEmployee).map_all(Into::into, Into::into)
					},

					p => p.unreachable(),
				};

				update::<A::Employee>(state.pool(), entities, code).await
			},
		)
		.put(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Put<(Department, String, String)>>| async move {
				const ACTION: Action = Action::Create;
				let (department, name, title) = request.into_args();
				let code = match state.employee_permissions(&user, ACTION).await?
				{
					Object::Employee => Code::Success,
					Object::EmployeeInDepartment if user.department().map_or(false, |d| d.id == department.id) =>
					{
						Code::Success
					},

					p @ Object::EmployeeInDepartment => return no_effective_perms(ACTION, p, Reason::NoDepartment),
					p @ Object::EmployeeSelf => return no_effective_perms(ACTION, p, Reason::ResourceExists),
					p => p.unreachable(),
				};

				create(code, A::Employee::create(state.pool(), department, name, title).await)
			},
		)
	}

	/// The handler for the [`routes::EXPENSE`](crate::api::routes::EXPENSE).
	pub fn expense(&self) -> MethodRouter<ServerState<A::Db>>
	{
		async fn retain_matching<A>(
			pool: &Pool<A::Db>,
			user: &User,
			entities: &mut Vec<Expense>,
			permission: Object,
		) -> sqlx::Result<()>
		where
			A: Adapter,
		{
			let e = user.employee().unwrap();
			let matching: HashSet<_> = A::Timesheet::retrieve(pool, MatchTimesheet {
				expenses: MatchExpense {
					id: Match::Or(entities.iter().map(|x| x.id.into()).collect()),
					..Default::default()
				}
				.into(),
				..match permission
				{
					Object::ExpensesInDepartment => MatchJob::from(MatchDepartment::from(e.department.id)).into(),
					Object::CreatedExpenses => MatchEmployee::from(e.id).into(),
					_ => permission.unreachable(),
				}
			})
			.await
			.map(|vec| vec.into_iter().flat_map(|t| t.expenses.into_iter().map(|x| x.id)).collect())?;

			entities.retain(|x| matching.contains(&x.id));
			Ok(())
		}

		/// If a `$user` does not have the [`Object::Expenses`] permission for `$action`, and they have no employee
		/// record, then they effectively cannot retrieve expenses.
		macro_rules! enforce_effective_permissions {
			($user:ident, $action:ident, $permission:ident) => {
				if $permission != Object::Expenses && $user.employee().is_none()
				{
					return no_effective_perms($action, $permission, match $permission == Object::CreatedExpenses
					{
						true => Reason::NoEmployee,
						false => Reason::NoDepartment,
					})
					.map_all(Into::into, Into::into);
				}
			};
		}

		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<Expense>>| async move {
				const ACTION: Action = Action::Delete;
				let permission = state.expense_permissions(&user, ACTION).await?;
				enforce_effective_permissions!(user, ACTION, permission);

				let mut entities = request.into_entities();

				let code = match permission
				{
					Object::Expenses => Code::Success,

					// The user can only post expenses iff they are in the same department, or were created
					// by that user.
					p =>
					{
						retain_matching::<A>(state.pool(), &user, &mut entities, p)
							.await
							.map_err(DeleteResponse::from)?;

						Code::SuccessForPermissions
					},
				};

				delete::<A::Expenses>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchExpense>>| async move {
				const ACTION: Action = Action::Retrieve;
				let permission = state.expense_permissions(&user, ACTION).await?;
				enforce_effective_permissions!(user, ACTION, permission);

				let condition = request.into_condition();

				let mut vec = A::Expenses::retrieve(state.pool(), condition)
					.await
					.map_err(|e| Response::from(Post::<Expense>::from(Status::from(&e))))?;

				let code = match permission
				{
					Object::Expenses => Code::Success,

					// The user can only post expenses iff they are in the same department, or were created
					// by that user.
					p =>
					{
						retain_matching::<A>(state.pool(), &user, &mut vec, p)
							.await
							.map_err(|e| Response::from(Post::from(Status::from(&e))))?;

						Code::SuccessForPermissions
					},
				};

				Ok::<_, Response<_>>(Response::from(Post::new(vec, code.into())))
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<Expense>>| async move {
				const ACTION: Action = Action::Update;
				let permission = state.expense_permissions(&user, ACTION).await?;
				enforce_effective_permissions!(user, ACTION, permission);

				let mut entities = request.into_entities();

				let code = match permission
				{
					Object::Expenses => Code::Success,

					// The user can only post expenses iff they are in the same department, or were created
					// by that user.
					p =>
					{
						retain_matching::<A>(state.pool(), &user, &mut entities, p)
							.await
							.map_err(PatchResponse::from)?;

						Code::SuccessForPermissions
					},
				};

				update::<A::Expenses>(state.pool(), entities, code).await
			},
		)
		.put(
			#[allow(clippy::type_complexity)]
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Put<(Vec<(String, Money, String)>, Id)>>| async move {
				#[warn(clippy::type_complexity)]
				const ACTION: Action = Action::Create;
				let permission = state.expense_permissions(&user, ACTION).await?;

				// A user has no effective permissions in two scenarios:
				//
				// 1. They have the `CreatedExpenses` permission
				// 2. They have the ExpensesInDepartment` permission but have no department
				if permission != Object::Expenses
				{
					let created = permission == Object::CreatedExpenses;
					if created || user.employee().is_none()
					{
						return no_effective_perms(
							ACTION,
							permission,
							created.then_some_or(Reason::ResourceExists, Reason::NoDepartment),
						)
						.map_all(Into::into, Into::into);
					}
				};

				let (expenses, timesheet_id) = request.into_args();

				let code = match permission
				{
					Object::Expenses => Code::Success,

					// The user can only post expenses iff they are in the same department, or were created
					// by that user.
					p =>
					{
						let matching: HashSet<_> = A::Timesheet::retrieve(state.pool(), match permission
						{
							Object::ExpensesInDepartment =>
							{
								MatchJob::from(MatchDepartment::from(user.department().unwrap().id)).into()
							},
							_ => permission.unreachable(),
						})
						.await
						.map_all(
							|vec| vec.into_iter().map(|t| t.id).collect(),
							|e| Response::from(Put::from(Status::from(&e))),
						)?;

						if !matching.contains(&timesheet_id)
						{
							return no_effective_perms(ACTION, p, Reason::NoResourceExists);
						}

						Code::Success
					},
				};

				let pool = state.pool();
				create(
					code,
					<A::Timesheet>::retrieve(pool, timesheet_id.into())
						.and_then(|t| A::Expenses::create(pool, expenses, (timesheet_id, t[0].time_begin)))
						.await,
				)
			},
		)
	}

	/// The handler for the [`routes::EXPORT`](crates::api::routes::EXPORT).
	pub fn export(&self) -> MethodRouter<ServerState<A::Db>>
	{
		const FORMAT: Format = Format::Markdown;
		const EXTENSION: &str = FORMAT.extension();
		routing::post(|State(state): State<ServerState<A::Db>>, Json(request): Json<request::Export>| async move {
			let history = HistoricalExchangeRates::history().await?;
			let requested_currency = request.currency();
			let contacts = A::Contact::retrieve(state.pool(), Default::default())
				.await
				.map_all(|vec| vec.into_iter().map(|c| (c.label, c.kind)).collect(), ExportResponse::from)?;

			stream::iter(request.jobs.into_iter().map(Result::<_, ExportResponse>::Ok))
				.and_then(|mut job| {
					let contacts = &contacts;
					let pool = state.pool();
					let history = &history;
					async move {
						let currency = requested_currency.unwrap_or_else(|| job.client.location.currency());
						let mut timesheets = A::Timesheet::retrieve(pool, MatchTimesheet {
							job: job.id.into(),
							time_end: Some(Match::Any).into(),
							..Default::default()
						})
						.await
						.map_err(ExportResponse::from)?;

						timesheets.sort_by_key(|t| t.time_begin);

						if currency != Default::default() || currency != job.invoice.hourly_rate.currency
						{
							let job_rates =
								HistoricalExchangeRates::index_ref_from(history, Some(job.date_open.into()));
							job.exchange_mut(currency, job_rates);
							timesheets.iter_mut().for_each(|t| {
								let rates = HistoricalExchangeRates::index_ref_from(history, Some(t.time_begin.into()));
								t.exchange_mut_historically(currency, rates, job_rates);
							});
						}

						let export = FORMAT.export_job(&job, contacts, &timesheets).map_err(ExportResponse::from)?;
						Ok((format!("{}--{}.{EXTENSION}", job.client.name.replace(' ', "-"), job.id), export))
					}
				})
				.try_collect::<HashMap<_, _>>()
				.await
				.map(ExportResponse::from)
		})
	}

	/// The handler for the [`routes::HEALTHY`](crate::api::routes::USER).
	pub fn healthy(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::get(|| async move {
			// NOTE: due to axum_sessions, if the request gets this far, the server is healthy.
			return StatusCode::OK;
		})
	}

	/// The handler for the [`routes::JOB`](crate::api::routes::JOB).
	pub fn job(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<Job>>| async move {
				const ACTION: Action = Action::Delete;
				let mut entities = request.into_entities();
				let code = match state.job_permissions(&user, ACTION).await?
				{
					Object::Job => Code::Success,

					// HACK: no if-let guards…
					Object::JobInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|j| j.departments.iter().any(|d| d.id == id));
						Code::SuccessForPermissions
					},

					p @ Object::JobInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				delete::<A::Job>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchJob>>| async move {
				const ACTION: Action = Action::Retrieve;
				let mut condition = request.into_condition();

				let code = match state.job_permissions(&user, ACTION).await?
				{
					Object::Job => Code::Success,

					// HACK: no if-let guards…
					Object::JobInDepartment if user.employee().is_some() =>
					{
						condition.departments &= MatchDepartment::from(user.department().unwrap().id).into();
						Code::SuccessForPermissions
					},

					p @ Object::JobInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment);
					},

					p => p.unreachable(),
				};

				retrieve::<A::Job>(state.pool(), condition, code).await
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<Job>>| async move {
				const ACTION: Action = Action::Update;
				let mut entities = request.into_entities();
				let code = match state.job_permissions(&user, ACTION).await?
				{
					Object::Job => Code::Success,

					// HACK: no if-let guards…
					Object::JobInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|j| j.departments.iter().any(|d| d.id == id));
						Code::SuccessForPermissions
					},

					p @ Object::JobInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				update::<A::Job>(state.pool(), entities, code).await
			},
		)
		.put(
			#[allow(clippy::type_complexity)]
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<
				request::Put<(
					Organization,
					Option<DateTime<Utc>>,
					DateTime<Utc>,
					BTreeSet<Department>,
					Serde<Duration>,
					Invoice,
					String,
					String,
				)>,
			>| async move {
				#[warn(clippy::type_complexity)]
				const ACTION: Action = Action::Create;
				let (client, date_close, date_open, departments, serde_increment, invoice, notes, objectives) =
					request.into_args();

				let increment = serde_increment.into_inner();
				let code = match state.job_permissions(&user, ACTION).await?
				{
					Object::Job => Code::Success,
					Object::JobInDepartment
						if user.department().map_or(false, |d| departments.iter().any(|d2| d2.id == d.id)) =>
					{
						Code::Success
					},

					p @ Object::JobInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				create(
					code,
					state
						.pool()
						.begin()
						.and_then(|mut tx| async move {
							let j = A::Job::create(
								&mut tx,
								client,
								date_close,
								date_open,
								departments,
								increment,
								invoice,
								notes,
								objectives,
							)
							.await?;

							tx.commit().await?;
							Ok(j)
						})
						.await,
				)
			},
		)
	}

	/// The handler for the [`routes::LOCATION`](crate::api::routes::LOCATION).
	pub fn location(&self) -> MethodRouter<ServerState<A::Db>>
	{
		route!(Location, (Option<Currency>, String, Option<Location>), currency, name, outer)
	}

	/// The handler for the [`routes::LOGIN`](crate::api::routes::LOGIN).
	pub fn login(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::post(
			|mut auth: AuthContext<A::Db>,
			 State(state): State<ServerState<A::Db>>,
			 TypedHeader(credentials): TypedHeader<Authorization<Basic>>| {
				async move {
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

					PasswordHash::new(user.password()).map_or_else(
						|e| {
							tracing::error!(
								"Failed to decode user {}'s password hash stored in database",
								user.username()
							);
							Err(LoginResponse::new(
								StatusCode::INTERNAL_SERVER_ERROR,
								Status::new(Code::EncodingError, e.to_string()),
								None,
							))
						},
						|hash| {
							Argon2::default().verify_password(credentials.password().as_bytes(), &hash).map_err(|e| {
								tracing::info!("Invalid login attempt for user {}", user.username());
								LoginResponse::from(e)
							})
						},
					)?;

					// HACK: no if-let chain…
					if let Some(result) = user.password_expires()
					{
						let date = result?;
						if date < Utc::now()
						{
							tracing::info!("User {} attempted to login with expired password", user.username());
							return Err(LoginResponse::expired(date));
						}
					}

					match auth.login(&user).await
					{
						Ok(_) => Ok(LoginResponse::from(user)),
						Err(e) =>
						{
							const CODE: Code = Code::LoginError;
							tracing::error!("Failed to to log in user {}: {e}", user.username());
							Err(LoginResponse::from(Status::new(CODE, e.to_string())))
						},
					}
				}
				.instrument(tracing::info_span!("login_handler"))
			},
		)
	}

	/// The handler for the [`routes::LOGOUT`](crate::api::routes::LOGOUT).
	pub fn logout(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::post(|mut auth: AuthContext<A::Db>| {
			async move {
				auth.logout().await;
				LogoutResponse::from(Code::Success)
			}
			.instrument(tracing::info_span!("logout_handler"))
		})
	}

	/// Create a new [`Handler`].
	pub const fn new() -> Self
	{
		Self { phantom: PhantomData }
	}

	/// The handler for the [`routes::ORGANIZATION`](crate::api::routes::ORGANIZATION).
	pub fn organization(&self) -> MethodRouter<ServerState<A::Db>>
	{
		route!(Organization, (Location, String), location, name)
	}

	/// The handler for the [`routes::ROLE`](crate::api::routes::ROLE).
	pub fn role(&self) -> MethodRouter<ServerState<A::Db>>
	{
		route!(Role, (String, Option<Serde<Duration>>), name, password_ttl = password_ttl.map(Serde::into_inner))
	}

	/// The handler for the [`routes::TIMESHEET`](crate::api::routes::TIMESHEET).
	pub fn timesheet(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<Timesheet>>| async move {
				const ACTION: Action = Action::Delete;
				let mut entities = request.into_entities();
				let code = match state.timesheet_permissions(&user, ACTION).await?
				{
					Object::Timesheet => Code::Success,

					// HACK: no if-let guards
					Object::TimesheetInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|t| t.job.departments.iter().any(|d| d.id == id));
						Code::SuccessForPermissions
					},

					// HACK: no if-let guards
					Object::CreatedTimesheet if user.employee().is_some() =>
					{
						let id = user.employee().unwrap().id;
						entities.retain(|t| t.employee.id == id);
						Code::SuccessForPermissions
					},

					p @ Object::TimesheetInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p @ Object::CreatedTimesheet =>
					{
						return no_effective_perms(ACTION, p, Reason::NoEmployee).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				delete::<A::Timesheet>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchTimesheet>>| async move {
				const ACTION: Action = Action::Retrieve;
				let mut condition = request.into_condition();
				let code = match state.timesheet_permissions(&user, ACTION).await?
				{
					Object::Timesheet => Code::Success,

					// HACK: no if-let guards
					Object::TimesheetInDepartment if user.employee().is_some() =>
					{
						condition.job.departments &= MatchDepartment::from(user.department().unwrap().id).into();
						Code::SuccessForPermissions
					},

					// HACK: no if-let guards
					Object::CreatedTimesheet if user.employee().is_some() =>
					{
						condition.employee.id &= user.employee().unwrap().id.into();
						Code::SuccessForPermissions
					},

					p @ Object::TimesheetInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment);
					},

					p @ Object::CreatedTimesheet =>
					{
						return no_effective_perms(ACTION, p, Reason::NoEmployee);
					},

					p => p.unreachable(),
				};

				retrieve::<A::Timesheet>(state.pool(), condition, code).await
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<Timesheet>>| async move {
				const ACTION: Action = Action::Update;
				let mut entities = request.into_entities();
				let code = match state.timesheet_permissions(&user, ACTION).await?
				{
					Object::Timesheet => Code::Success,

					// HACK: no if-let guards
					Object::TimesheetInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|t| t.job.departments.iter().any(|d| d.id == id));
						Code::SuccessForPermissions
					},

					// HACK: no if-let guards
					Object::CreatedTimesheet if user.employee().is_some() =>
					{
						let id = user.employee().unwrap().id;
						entities.retain(|t| t.employee.id == id);
						Code::SuccessForPermissions
					},

					p @ Object::TimesheetInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p @ Object::CreatedTimesheet =>
					{
						return no_effective_perms(ACTION, p, Reason::NoEmployee).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				update::<A::Timesheet>(state.pool(), entities, code).await
			},
		)
		.put(
			#[allow(clippy::type_complexity)]
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<
				request::Put<(
					Employee,
					Vec<(String, Money, String)>,
					Job,
					DateTime<Utc>,
					Option<DateTime<Utc>>,
					String,
				)>,
			>| async move {
				#[warn(clippy::type_complexity)]
				const ACTION: Action = Action::Create;
				let (employee, expenses, job, time_begin, time_end, work_notes) = request.into_args();
				let code = match state.timesheet_permissions(&user, ACTION).await?
				{
					Object::Timesheet => Code::Success,
					Object::TimesheetInDepartment
						if user.department().map_or(false, |d| job.departments.iter().any(|d2| d2.id == d.id)) =>
					{
						Code::Success
					},

					p @ Object::TimesheetInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p @ Object::CreatedTimesheet =>
					{
						return no_effective_perms(ACTION, p, Reason::ResourceExists).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				create(
					code,
					state
						.pool()
						.begin()
						.and_then(|mut tx| async move {
							let t = A::Timesheet::create(
								&mut tx, employee, expenses, job, time_begin, time_end, work_notes,
							)
							.await?;

							tx.commit().await?;
							Ok(t)
						})
						.await,
				)
			},
		)
	}

	/// The handler for the [`routes::USER`](crate::api::routes::USER).
	pub fn user(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::delete(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Delete<User>>| async move {
				const ACTION: Action = Action::Delete;
				let mut entities = request.into_entities();
				let code = match state.user_permissions(&user, ACTION).await?
				{
					Object::User => Code::Success,

					// HACK: no if-let guards
					Object::UserInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|u| u.employee().map_or(false, |e| e.department.id == id));
						Code::SuccessForPermissions
					},

					Object::UserSelf =>
					{
						let id = user.id();
						entities.retain(|u| u.id() == id);
						Code::SuccessForPermissions
					},

					p @ Object::UserInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				delete::<A::User>(state.pool(), entities, code).await
			},
		)
		.post(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Post<MatchUser>>| async move {
				const ACTION: Action = Action::Retrieve;
				let mut condition = request.into_condition();
				let code = match state.user_permissions(&user, ACTION).await?
				{
					Object::User => Code::Success,

					// HACK: no if-let guards
					Object::UserInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						condition.employee = match condition.employee
						{
							MatchOption::Any => Some(MatchDepartment::from(id).into()).into(),
							e => e.map(|mut m| {
								m.department.id &= id.into();
								m
							}),
						};

						Code::SuccessForPermissions
					},

					Object::UserSelf =>
					{
						condition.id &= user.id().into();
						Code::SuccessForPermissions
					},

					p @ Object::UserInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment);
					},

					p => p.unreachable(),
				};

				retrieve::<A::User>(state.pool(), condition, code).await
			},
		)
		.patch(
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Patch<User>>| async move {
				const ACTION: Action = Action::Update;
				let mut entities = request.into_entities();
				let code = match state.user_permissions(&user, ACTION).await?
				{
					Object::User => Code::Success,

					// HACK: no if-let guards
					Object::UserInDepartment if user.employee().is_some() =>
					{
						let id = user.department().unwrap().id;
						entities.retain(|u| u.employee().map_or(false, |e| e.department.id == id));
						Code::SuccessForPermissions
					},

					Object::UserSelf =>
					{
						let id = user.id();
						entities.retain(|u| u.id() == id);
						Code::SuccessForPermissions
					},

					p @ Object::UserInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				// retrieve all passwords which were potentially updated.
				let passwords = A::User::retrieve(
					state.pool(),
					entities
						.iter()
						.filter_map(|u| u.password.is_empty().then_some_or(None, Some(u.id())))
						.collect::<Match<_>>()
						.into(),
				)
				.await
				.map(|vec| vec.into_iter().map(|user| (user.id(), user.password)).collect::<HashMap<_, _>>())?;

				// ensure that the "new" passwords are actually new, and then update the password set date.
				entities.iter_mut().try_for_each(|user| {
					// TODO: no if-let chain… `if let Some(password) = post() && password != user.password {}`
					if passwords.get(&user.id()).map_or(false, |password| user.password.ne(password))
					{
						user.hash_password()?;
						user.password_set = Utc::now();
					}

					Ok::<_, HashError>(())
				})?;

				update::<A::User>(state.pool(), entities, code).await
			},
		)
		.put(
			#[allow(clippy::type_complexity)]
			|Extension(user): Extension<User>,
			 State(state): State<ServerState<A::Db>>,
			 Json(request): Json<request::Put<(Option<Employee>, String, Role, String)>>| async move {
				#[warn(clippy::type_complexity)]
				const ACTION: Action = Action::Create;
				let (employee, password, role, username) = request.into_args();
				let code = match state.user_permissions(&user, ACTION).await?
				{
					Object::User => Code::Success,
					Object::UserInDepartment
						if user.department().zip(employee.as_ref()).map_or(false, |(d, e)| d.id == e.department.id) =>
					{
						Code::Success
					},

					p @ Object::UserSelf => return no_effective_perms(ACTION, p, Reason::ResourceExists),
					p @ Object::UserInDepartment =>
					{
						return no_effective_perms(ACTION, p, Reason::NoDepartment).map_all(Into::into, Into::into);
					},

					p => p.unreachable(),
				};

				create(code, A::User::create(state.pool(), employee, password, role, username).await)
			},
		)
	}

	/// The handler for the [`routes::WHO_AM_I`](crate::api::routes::USER).
	pub fn who_am_i(&self) -> MethodRouter<ServerState<A::Db>>
	{
		routing::post(|Extension(user): Extension<User>| async move { WhoAmIResponse::from(user) })
	}
}
