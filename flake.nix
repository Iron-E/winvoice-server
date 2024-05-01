{
	description = "winvoice-server dev env / packaging";

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = inputs @ { self, nixpkgs, ... }:
	let
		inherit (nixpkgs) lib;
		inherit (self) outputs;
		name = "winvoice-server";
		genSystems = lib.genAttrs ["aarch64-darwin" "aarch64-linux" "i686-linux" "x86_64-darwin" "x86_64-linux"];

		mkPkgs = system: import nixpkgs {
			inherit system;
			config.allowUnfree = true;
			overlays = (builtins.attrValues outputs.overlays) ++ [
				inputs.fenix.overlays.default
			];
		};

		mkToolchain = fenix: fenix.fromToolchainFile {
			file = ./rust-toolchain.toml;
			sha256 = "sha256-7QfkHty6hSrgNM0fspycYkRcB82eEqYa4CoAJ9qA3tU=";
		};
	in {
		devShells = genSystems (system:
		let pkgs = mkPkgs system;
		in {
			default = pkgs.mkShell {
				inherit name;
				inputsFrom = with pkgs; [ openssl ];
				packages = with pkgs; [
					(mkToolchain fenix)
					kind kubectl kubectl-cnpg kubectx
					mkcert
					terraform
				];
			};
		});

		packages = genSystems (system:
		let
			pkgs = mkPkgs system;
			toolchain = mkToolchain pkgs.fenix;

			winvoice-server = (pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; }).buildRustPackage {
				pname = name;
				version = "0.6.4";

				src = ./.;
				cargoLock = {
					lockFile = ./Cargo.lock;
					outputHashes = {
						"sqlx-0.6.3" = "sha256-wuoZkbuRlzV1wNNQ01Dmvy8Q4sJ1ivvZ3fo8E1p0pZw=";
						"winvoice-adapter-0.27.0" = "sha256-5W1bM6uIm4UG/sQF277fk/ycrUPZfR28+z4nJt8ig9I=";
						"winvoice-adapter-postgres-0.20.1" = "sha256-Qu/OFMrZ0qpEBFjtG5ShWfCpi1sHWue6QCJT+1mSN1I=";
						"winvoice-export-0.8.1" = "sha256-ZmcSzeLxTELvWgPQePKrzPt+9w7FI7Q0qTzKvrnoLuQ=";
						"winvoice-match-0.15.0" = "sha256-3ms0JV6NVtDe4N7C3wcCB/xWHa6kRvx3vCwR1Z/7bt0=";
						"winvoice-schema-0.16.4" = "sha256-2IsZTGkHxLIl6lyjUAHwBZvkRD6335x+Wkgw2BcpOhY=";
					};
				};

				buildInputs = with pkgs; [ openssl ];
				nativeBuildInputs = with pkgs; [ makeWrapper pkg-config ];

				checkFlags = [
					# `preCheck` doesn't work with `buildRustPackage`, so `watchman`'s state dir can't be created before the test
					"--skip=args::tests::watch_permissions"
				];

				postFixup = ''
					wrapProgram "$out/bin/${name}" \
						--suffix PATH : "${lib.makeBinPath [ pkgs.watchman ]}"
				'';

				meta = {
					description = "A Winvoice backend server with API";
					homepage = "https://github.com/Iron-E/winvoice-server";
					license = lib.licenses.gpl3Plus;
					mainProgram = name;
				};
			};
		in {
			inherit winvoice-server;
			default = winvoice-server;
		});

		overlays = { };
	};
}
