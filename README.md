# rust-gnark

Rust bindings for the [gnark](https://github.com/consensys/gnark) Groth16 BN254 proving system.

## Usage

```toml
[dependencies]
rust-gnark = "0.0.1"
```

```rust
use rust_gnark::{init, groth16_prove, groth16_verify};

init()?;

let result = groth16_prove("circuit.r1cs", "circuit.pk", r#"{"X": "3", "Y": "35"}"#)?;
let valid = groth16_verify("circuit.r1cs", "circuit.vk", &result)?;
```

No Go toolchain required -- prebuilt static libraries are bundled in the published crate.

## Supported targets

| Target | Platform |
|--------|----------|
| `aarch64-apple-ios` | iOS device |
| `aarch64-apple-ios-sim` | iOS simulator (ARM64) |
| `x86_64-apple-ios` | iOS simulator (x86_64) |
| `aarch64-apple-darwin` | macOS (Apple Silicon) |
| `x86_64-apple-darwin` | macOS (Intel) |
| `aarch64-linux-android` | Android (ARM64) |
| `x86_64-linux-android` | Android (x86_64) |
| `x86_64-unknown-linux-gnu` | Linux (x86_64) |
| `aarch64-unknown-linux-gnu` | Linux (ARM64) |

WASM is not supported (`c-archive` does not target WASM).

## Development

Requires Go 1.24+ to compile the Go wrapper from source:

```sh
cargo test --all
```

Cross-compilation is auto-detected from the Rust `TARGET`, or set manually:

```sh
RUST_GNARK_GO_ENVS="GOOS=ios;GOARCH=arm64;CC=/path/to/cc" cargo build
```

## License

MIT
