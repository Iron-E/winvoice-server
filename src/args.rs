mod command;
#[cfg(feature = "postgres")]
mod postgres;

use core::time::Duration;
use std::{net::SocketAddr, path::PathBuf};

use axum::http::HeaderValue;
use axum_server::tls_rustls::RustlsConfig;
use casbin::{CoreApi, Enforcer};
use clap::{
	builder::{PossibleValuesParser, TypedValueParser},
	Parser,
};
use command::Command;
use futures::TryFutureExt;
use tokio::fs;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
#[cfg(feature = "watchman")]
use {
	crate::lock::Lock,
	std::path::Path,
	tracing::{instrument, Instrument},
	watchman_client::{
		expr::{Expr, NameTerm},
		fields::NameOnly,
		pdu::SubscribeRequest,
		CanonicalPath,
		Connector,
		SubscriptionData,
	},
};

use crate::{
	dyn_result::{DynError, DynResult},
	lock,
	utils,
};

/// Winvoice is a tool to track and generate invoices from the command line. Pass --help for more.
///
/// It is capable of managing information about clients, employees, jobs, timesheets, and exporting
/// the information into the format of your choice.
#[derive(Clone, Debug, Parser)]
#[command(version = "0.1.0")]
pub struct Args
{
	/// The IP and port to bind the Winvoice server to.
	#[arg(default_value = "127.0.0.1:3000", long, short, value_name = "IP:PORT")]
	address: SocketAddr,

	/// The file containing the certificate to use for TLS. Must be in PEM format.
	#[arg(long, short, value_name = "FILE")]
	certificate: PathBuf,

	/// The Winvoice adapter which will be used for this server.
	#[command(subcommand)]
	command: Command,

	/// The amount of time that a [`Database`](sqlx::Database) connection may be held open even
	/// though no activity has occurred.
	#[arg(
		default_value = "30s",
		long,
		short = 'I',
		value_name = "DURATION",
		value_parser = humantime::parse_duration,
	)]
	connection_idle: Duration,

	/// The domain name that will be used when creating cookies.
	#[arg(long, short = 'D', value_name = "DOMAIN_NAME")]
	cookie_domain: Option<String>,

	/// The key which will be used to sign cookies. Should be securely generated, rather than
	/// chosen.
	///
	/// TODO: allow changing without restarting the server
	#[arg(long, short = 'S', value_name = "KEY")]
	cookie_secret: Option<Vec<u8>>,

	/// A file which contains origins (one per line) that are allowed in Cross-Origin Resource Sharing.
	#[arg(long, short = 'O', value_name = "FILE")]
	cors_allow_origin: PathBuf,

	/// The file containing the key to use for TLS. Must be in PEM format.
	#[arg(long, short, value_name = "FILE")]
	key: PathBuf,

	/// The directory where the log is stored.
	///
	/// When unspecified, uses [`dirs::state_dir`] or [`dirs::data_local_dir`]— whichever can be
	/// resolved.
	#[arg(long, short = 'L')]
	log_dir: Option<PathBuf>,

	/// How often new log files will be generated.
	#[arg(
		default_value_t = String::from("daily"),
		long,
		short = 'R',
		value_parser = ["daily", "hourly", "minutely", "never"],
	)]
	log_rotation: String,

	/// The log level for the server. Any events which occur below this level are not logged.
	#[arg(
		default_value_t = LevelFilter::ERROR,
		long,
		short,
		value_parser = PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"]).map(|v| v.parse::<LevelFilter>().unwrap()),
	)]
	log_level: LevelFilter,

	/// A [`casbin`] model. See [the docs](https://casbin.org/docs/supported-models) for more
	/// information.
	///
	/// If none is passed, the [`DefaultModel`](casbin::DefaultModel) will be used.
	///
	/// Should be in the same folder as the `--permissions-policy`.
	#[arg(long, short = 'M', value_name = "FILE")]
	permissions_model: Option<String>,

	/// A [`casbin`] policy. Try [the editor](https://casbin.org/editor).
	#[arg(long, short, value_name = "FILE")]
	permissions_policy: String,

	/// The amount of time that a session is valid for.
	#[arg(
		default_value = "4hr",
		long,
		short,
		value_name = "DURATION",
		value_parser = humantime::parse_duration,
	)]
	session_ttl: Duration,

	/// The maximum duration to run commands server before timing out (e.g. "5s", "15min").
	///
	/// When this argument is passed without a value (i.e. `--timeout`), a duration of 30 seconds
	/// is set.
	#[arg(
		default_missing_value = "30s",
		num_args = 0..=1,
		long,
		short,
		value_name = "DURATION",
		value_parser = humantime::parse_duration,
	)]
	timeout: Option<Duration>,
}

impl Args
{
	/// Run the Winvoice server.
	pub async fn run(self) -> DynResult<()>
	{
		let _guard = init_tracing(self.log_level, self.log_dir, &self.log_rotation)?;

		let model_path = self.permissions_model.map(|m| -> &'static str { m.leak() });
		let policy_path: &'static str = self.permissions_policy.leak();

		let (origins_file, permissions, tls) = futures::try_join!(
			fs::read_to_string(self.cors_allow_origin).err_into(),
			Enforcer::new(model_path, policy_path).map_ok(lock::new).err_into(),
			RustlsConfig::from_pem_file(self.certificate, self.key).err_into::<DynError>(),
		)?;

		let origins = origins_file.lines().into_iter().map(HeaderValue::from_str).collect::<Result<Vec<_>, _>>()?;

		#[cfg(feature = "watchman")]
		if let Err(e) = init_watchman(permissions.clone(), model_path, policy_path).await
		{
			tracing::error!("Failed to enable hot-reloading permissions: {e}");
		}

		macro_rules! run {
			($cmd:expr, $($Variant:ident $feature:literal),+) => {
				match $cmd
				{
					$(#[cfg(feature = $feature)]
					Command::$Variant(p) => p.run(
						self.address,
						self.connection_idle,
						self.cookie_domain,
						self.cookie_secret.unwrap_or_else(utils::cookie_secret),
						origins,
						permissions,
						self.session_ttl,
						self.timeout,
						tls,
					)),+
				}
			}
		}

		run!(self.command, Postgres "postgres").await
	}
}

/// Initialize [`tracing`] using the [`tracing_appender`] implementation of
/// [`tracing_subscriber`].
fn init_tracing(log_level: LevelFilter, log_dir: Option<PathBuf>, log_rotation: &str) -> DynResult<WorkerGuard>
{
	let dir = log_dir
		.or_else(|| {
			dirs::state_dir().or_else(dirs::data_local_dir).map(|mut d| {
				d.push("winvoice-server");
				d
			})
		})
		.ok_or_else(|| "Could not find suitable `--log-dir`. Please specify it manually.".to_owned())?;

	let (non_blocking, guard) = tracing_appender::non_blocking(match log_rotation
	{
		"daily" => tracing_appender::rolling::daily,
		"hourly" => tracing_appender::rolling::hourly,
		"minutely" => tracing_appender::rolling::minutely,
		"never" => tracing_appender::rolling::never,
		r => unreachable!("`--log-rotation` was an unexpected value: {r}"),
	}(dir, "server.log"));

	tracing_subscriber::fmt().with_max_level(log_level).with_writer(non_blocking).try_init()?;
	Ok(guard)
}

/// Watch the `model_path` and `policy_path` for changes, reloading the `permissions` when they are
/// changed.
///
/// This allows [`winvoice_server`]'s permissions to be hot-reloaded while the server is
/// running.
#[cfg_attr(feature = "watchman", instrument(level = "trace", skip(permissions)))]
#[cfg(feature = "watchman")]
pub(crate) async fn init_watchman(
	permissions: Lock<Enforcer>,
	model_path: Option<&'static str>,
	policy_path: &'static str,
) -> DynResult<()>
{
	/// Post the [`file_name`](Path::file_name) of the [`str`]
	fn file_name(s: &str) -> PathBuf
	{
		PathBuf::from(Path::new(s).file_name().unwrap())
	}

	let client = Connector::new().connect().await?;

	let path = CanonicalPath::canonicalize(Path::new(policy_path).parent().unwrap())?;
	let root = client.resolve_root(path).await?;

	let mut names = NameTerm { paths: vec![file_name(policy_path)], wholename: false };
	if let Some(p) = model_path
	{
		names.paths.push(file_name(p));
	}

	let (mut subscription, _) = client
		.subscribe::<NameOnly>(&root, SubscribeRequest {
			expression: Some(Expr::Name(names)),
			fields: vec!["name"],
			..Default::default()
		})
		.await?;

	tokio::spawn(
		async move {
			tracing::info!("Watching for file changes");
			loop
			{
				match subscription.next().await
				{
					Ok(SubscriptionData::Canceled) =>
					{
						tracing::error!("Watchman stopped unexpectedly. Hot reloading permissions is disabled.");
						break;
					},
					Ok(SubscriptionData::FilesChanged(query)) =>
					{
						tracing::debug!("Notified of file change: {query:#?}");
						let mut p = permissions.write().await;
						*p = match Enforcer::new(model_path, policy_path).await
						{
							Ok(e) => e,
							Err(e) =>
							{
								tracing::info!("Could not reload permissions: {e}");
								continue;
							},
						};
						tracing::trace!("Successfully processed file change(s)");
					},
					Ok(event) => tracing::trace!("Notified of ignored event: {event:?}"),
					Err(e) =>
					{
						tracing::error!(
							"Encountered an error while watching for file changes: {e}. Hot reloading permissions is \
							 disabled"
						);
						break;
					},
				}
			}

			Ok::<_, watchman_client::Error>(())
		}
		.instrument(tracing::error_span!("hot_reload_permissions")),
	);

	Ok(())
}

#[allow(clippy::std_instead_of_core, clippy::str_to_string)]
#[cfg(all(feature = "watchman", test))]
mod tests
{
	use std::{fs::OpenOptions, io::Write};

	use tracing_test::traced_test;

	use super::*;
	use crate::utils;

	#[tokio::test]
	#[traced_test]
	async fn watch_permissions() -> DynResult<()>
	{
		let wait = Duration::from_millis(30);
		let (model_path, policy_path) = utils::init_model_and_policy_files(
			"args::watch_permissions",
			utils::Model::Acl.to_string(),
			"p, alice, data1, read\n",
		)
		.await?;

		let model_path_str: &'static str = model_path.to_string_lossy().into_owned().leak();
		let policy_path_str: &'static str = policy_path.to_string_lossy().into_owned().leak();

		let permissions = Enforcer::new(model_path_str, policy_path_str).await.map(lock::new)?;
		super::init_watchman(permissions.clone(), Some(model_path_str), policy_path_str).await?;

		{
			// Assert permissions are correct
			let p = permissions.read().await;
			assert!(p.enforce(("alice", "data1", "read"))?);
			assert!(!p.enforce(("bob", "data2", "write"))?);
		}

		{
			let mut file = OpenOptions::new().append(true).open(&policy_path)?;
			writeln!(file, "p, bob, data2, write")?;
		}

		{
			// Assert permissions update when policy is written to
			tokio::time::sleep(wait).await;
			let p = permissions.read().await;
			assert!(p.enforce(("alice", "data1", "read"))?);
			assert!(p.enforce(("bob", "data2", "write"))?);
		}

		fs::write(
			&policy_path,
			r#"p, alice, data1, read
p, bob, data2, write
p, data2_admin, data2, read
p, data2_admin, data2, write
g, alice, data2_admin
"#,
		)
		.await?;

		{
			// Assert permissions remain valid when policy is written to with content that the model
			// doesn't support
			tokio::time::sleep(wait).await;
			let p = permissions.read().await;
			assert!(p.enforce(("alice", "data1", "read"))?);
			assert!(!p.enforce(("alice", "data2", "write"))?);
			assert!(p.enforce(("bob", "data2", "write"))?);
			assert!(p.enforce(("data2_admin", "data2", "write"))?);
		}

		fs::write(&model_path, utils::Model::Rbac.to_string()).await?;

		{
			// Assert update to model can fix bad policy
			tokio::time::sleep(wait).await;
			let p = permissions.read().await;
			assert!(p.enforce(("alice", "data1", "read"))?);
			assert!(p.enforce(("bob", "data2", "write"))?);
			assert!(p.enforce(("alice", "data2", "write"))?);
			assert!(p.enforce(("data2_admin", "data2", "write"))?);
		}

		Ok(())
	}
}
