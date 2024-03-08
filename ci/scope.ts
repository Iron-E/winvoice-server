import { setTo } from '@iron-e/scabbard';
import { CARGO_HACK_VERSION } from '@iron-e/scabbard/rust/scope/client';

setTo('0.6.20', CARGO_HACK_VERSION);

/**
 * Default arguments for cargo hack.
 */
export const CARGO_HACK_ARGS = [
	'--feature-powerset',
	'--at-least-one-of', 'bin,postgres',
	'--exclude-features', 'watchman',
	'--skip', 'watchman',
];
