import '@iron-e/scabbard/db';
import '@iron-e/scabbard/rust';
import { CARGO_HACK_ARGS as hackArgs } from './scope';
import { Container } from '@dagger.io/dagger';
import { enqueue } from '@iron-e/scabbard';
import { exec } from 'node:child_process';
import { promisify } from 'util';
import { WITH_CARGO_HACK } from '@iron-e/scabbard/rust/scope';

enqueue(async (client, inject) => {
	const grepCargoLock = await promisify(exec)("grep 'name = .winvoice-adapter-postgres.' Cargo.lock -C 3 | grep 'source'");
	if (grepCargoLock.stderr.length > 1) {
		throw Error(grepCargoLock.stderr);
	}

	/** grep returns `source = "git+<URL>"`. this retrieves the `<URL>` part */
	const winvoicePgUri = grepCargoLock.stdout.match(/(?<="git\+)\S+(?=")/)?.[0] ?? '';

	/** the `<URL>` has `<GITHUB_REPO>?branch=<BRANCH>#<COMMIT>`. Select the `<COMMIT>` part */
	const winvoicePgCommit = winvoicePgUri.match(/(?<=#)\S+/)?.[0] ?? '';

	/** the `<URL>` has `<GITHUB_REPO>?branch=<BRANCH>#<COMMIT>`. Select the `<GITHUB_REPO>` part */
	const winvoicePgRepo = winvoicePgUri.match(/https:[^?#]+/)?.[0] ?? 'https://github.com/Iron-E/winvoice-adapter-postgres';

	/**
	 * The PG init scripts from the winvoice-adapter-postgres repo.
	 *
	 * @remarks
	 * Normally they would be run automatically when connecting to a new database,
	 * but it must be done manually when running tests.
	 */
	const winvoicePgInit = client
		.git(winvoicePgRepo)
		.commit(winvoicePgCommit)
		.tree()
		.directory('src/schema/initializable')
		;

	const postgres = client.dbService('postgres:16.2', {
		env: { POSTGRES_DB: 'winvoice-server', POSTGRES_PASSWORD: 'password', POSTGRES_USER: 'user' },
		initScriptDirs: [
			['src/server/auth/initializable_with_authorization', '/docker-entrypoint-initdb.d'],
			['src/server/db_session_store/initializable', '/docker-entrypoint-initdb.d'],
			[winvoicePgInit, '/docker-entrypoint-initdb.d'],
		],
	});

	const withCargo = (await inject(WITH_CARGO_HACK)).instance(Container);
	const output = await withCargo
		.withServiceBinding('db', postgres)
		.withEnvVariable('DATABASE_URL', 'postgresql://user:password@db/winvoice-server')
		.withEnvVariable('RUSTFLAGS', "-C target-feature=-crt-static")
		.withExecCargoHack('test', {
			// NOTE: tests *must* be run one at a time as they create and destroy the test roles,
			//       which would cause duplicate keys if done at the same time.
			commandArgs: ['--', '--test-threads', '1'],

			// FIXME: `watchman` not available on alpine, so just skip the for now…
			hackArgs: [...hackArgs, '--include-features', 'test-postgres'],
		})
		.stdout()
		;

	console.log(output);
});

await import.meta.filename.runPipelinesIfMain();
