//! Build script for rust-gnark.
//!
//! Two modes:
//! 1. **Published crate** (`prebuilt/<target>/` exists): Links the bundled library and header.
//!    Downstream consumers never need Go installed.
//! 2. **Development** (`go/` directory exists): Compiles Go from source.
//!    Requires Go toolchain (1.24+). Cross-compilation env vars are auto-detected
//!    from the Rust `TARGET`.
//!
//! Android targets use `-buildmode=c-shared` (`.so`) because Go does not support
//! `c-archive` on `GOOS=android`. All other targets use `c-archive` (`.a`).
//!
//! Cross-compilation can also be configured explicitly via the `RUST_GNARK_GO_ENVS`
//! environment variable (format: `"GOOS=ios;GOARCH=arm64;CC=/path/to/cc"`).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=go");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let target = env::var("TARGET").expect("TARGET not set");

    let is_android = target.contains("linux-android");
    let (buildmode, lib_name) = if is_android {
        ("c-shared", "libgnark.so")
    } else {
        ("c-archive", "libgnark.a")
    };

    let go_dir = manifest_dir.join("../go");
    let prebuilt_dir = manifest_dir.join("prebuilt").join(&target);

    if prebuilt_dir.exists() {
        let lib_src = prebuilt_dir.join(lib_name);
        let header_src = prebuilt_dir.join("libgnark.h");

        assert!(
            lib_src.exists(),
            "prebuilt/{target}/{lib_name} not found. Rebuild prebuilt libraries."
        );
        assert!(
            header_src.exists(),
            "prebuilt/{target}/libgnark.h not found. Rebuild prebuilt libraries."
        );

        std::fs::copy(&lib_src, out_dir.join(lib_name))
            .expect("Failed to copy prebuilt lib");
        std::fs::copy(&header_src, out_dir.join("libgnark.h"))
            .expect("Failed to copy prebuilt header");
    } else if go_dir.exists() {
        let dest = out_dir.join(lib_name);
        let go_envs = detect_go_cross_env(&target, &out_dir);

        let mut cmd = Command::new("go");
        cmd.current_dir(&go_dir).env("CGO_ENABLED", "1").args([
            "build",
            &format!("-buildmode={buildmode}"),
            "-ldflags=-s -w",
            "-gcflags=all=-l -B",
            "-o",
            dest.to_str().expect("Invalid output path"),
            ".",
        ]);

        for (k, v) in &go_envs {
            cmd.env(k, v);
        }

        let status = cmd.status().expect(
            "Go build failed. Is Go installed? \
             Development builds of rust-gnark require Go 1.24+.",
        );
        assert!(status.success(), "Go build failed with status: {status}");
    } else {
        panic!(
            "Neither prebuilt/{target} nor go/ directory found. \
             If consuming as a crate, prebuilt libs should be bundled. \
             If developing, ensure go/ directory exists and Go is installed."
        );
    }

    let header_path = out_dir.join("libgnark.h");
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().expect("Invalid header path"))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Failed to generate Rust bindings from libgnark.h");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Failed to write bindings.rs");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    if is_android {
        println!("cargo:rustc-link-lib=dylib=gnark");
    } else {
        println!("cargo:rustc-link-lib=static=gnark");
    }
    link_platform_deps(&target);
}

/// Auto-detect Go cross-compilation environment from the Rust `TARGET` triple.
///
/// Priority:
/// 1. `RUST_GNARK_GO_ENVS` env var (explicit override)
/// 2. Auto-detection from TARGET -> GOOS/GOARCH/CC mapping
///
/// For iOS targets, creates a temporary clang wrapper script in `OUT_DIR` that
/// invokes `xcrun` with the appropriate SDK and target triple.
///
/// For Android targets, locates the NDK clang from `ANDROID_NDK_HOME`.
fn detect_go_cross_env(target: &str, out_dir: &Path) -> Vec<(String, String)> {
    let manual = parse_go_envs();
    if !manual.is_empty() {
        return manual;
    }

    let (goos, goarch) = match target {
        t if t.contains("apple-ios") => {
            let arch = if t.starts_with("aarch64") {
                "arm64"
            } else {
                "amd64"
            };
            ("ios", arch)
        }
        t if t.contains("apple-darwin") => {
            let arch = if t.starts_with("aarch64") {
                "arm64"
            } else {
                "amd64"
            };
            ("darwin", arch)
        }
        t if t.contains("linux-android") => {
            let arch = if t.starts_with("aarch64") {
                "arm64"
            } else {
                "amd64"
            };
            ("android", arch)
        }
        t if t.contains("linux-gnu") => {
            let arch = if t.starts_with("aarch64") {
                "arm64"
            } else {
                "amd64"
            };
            ("linux", arch)
        }
        // Unknown target: let Go use host defaults (native build)
        _ => return Vec::new(),
    };

    let mut envs = vec![
        ("GOOS".into(), goos.into()),
        ("GOARCH".into(), goarch.into()),
    ];

    if let Some(cc) = detect_cc(target, out_dir) {
        envs.push(("CC".into(), cc));
    }

    envs
}

/// Detect the C compiler for cross-compilation targets.
///
/// Returns `None` for targets where the default system compiler works
/// (e.g., native builds, macOS arm64<->x86_64 cross-compilation via
/// universal clang).
fn detect_cc(target: &str, out_dir: &Path) -> Option<String> {
    match target {
        // iOS device: iphoneos SDK
        "aarch64-apple-ios" => Some(create_apple_cc_wrapper(
            out_dir,
            "iphoneos",
            "arm64-apple-ios13.0",
        )),
        // iOS simulator ARM64
        "aarch64-apple-ios-sim" => Some(create_apple_cc_wrapper(
            out_dir,
            "iphonesimulator",
            "arm64-apple-ios13.0-simulator",
        )),
        // iOS simulator x86_64
        "x86_64-apple-ios" => Some(create_apple_cc_wrapper(
            out_dir,
            "iphonesimulator",
            "x86_64-apple-ios13.0-simulator",
        )),
        // Android: use NDK clang
        t if t.contains("linux-android") => detect_android_cc(t),
        // Linux ARM64 cross-compilation from x86_64 host
        "aarch64-unknown-linux-gnu" => {
            let host = env::var("HOST").unwrap_or_default();
            if host.contains("x86_64") {
                Some("aarch64-linux-gnu-gcc".into())
            } else {
                None // native build on ARM64
            }
        }
        // macOS and native Linux: system compiler handles it
        _ => None,
    }
}

/// Create a shell wrapper script for Apple cross-compilation via `xcrun`.
///
/// The wrapper invokes `xcrun -sdk <sdk> clang -target <triple>` which
/// automatically resolves the SDK sysroot and applies the correct flags.
///
/// # Arguments
///
/// * `out_dir` - Directory to write the wrapper script
/// * `sdk` - Apple SDK name (e.g., `"iphoneos"`, `"iphonesimulator"`)
/// * `clang_target` - Clang target triple (e.g., `"arm64-apple-ios13.0"`)
///
/// # Returns
///
/// Absolute path to the generated wrapper script.
fn create_apple_cc_wrapper(out_dir: &Path, sdk: &str, clang_target: &str) -> String {
    // Use a unique name per SDK to avoid collisions when building
    // multiple iOS targets in the same workspace.
    let script_name = format!("cc_wrapper_{sdk}.sh");
    let script_path = out_dir.join(&script_name);
    let script_content =
        format!("#!/bin/sh\nexec xcrun -sdk {sdk} clang -target {clang_target} \"$@\"\n");

    std::fs::write(&script_path, script_content)
        .unwrap_or_else(|e| panic!("Failed to write CC wrapper {script_name}: {e}"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("Failed to chmod CC wrapper {script_name}: {e}"));
    }

    script_path
        .to_str()
        .expect("Invalid wrapper script path")
        .into()
}

/// Detect Android NDK clang for cross-compilation.
///
/// Searches for the NDK via `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` env vars.
/// Uses API level 21 (Android 5.0) as the minimum supported version.
fn detect_android_cc(target: &str) -> Option<String> {
    let ndk = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("ANDROID_NDK_ROOT"))
        .ok()?;

    // Detect host platform for NDK prebuilt path.
    // build.rs runs on the host, so cfg! reflects the build machine.
    let host_tag = if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "linux-x86_64"
    };

    let clang_name = match target {
        "aarch64-linux-android" => "aarch64-linux-android21-clang",
        "x86_64-linux-android" => "x86_64-linux-android21-clang",
        _ => return None,
    };

    let cc = format!("{ndk}/toolchains/llvm/prebuilt/{host_tag}/bin/{clang_name}");

    if Path::new(&cc).exists() {
        Some(cc)
    } else {
        println!(
            "cargo:warning=Android NDK clang not found at {cc}. \
             Cross-compilation may fail. Set ANDROID_NDK_HOME correctly."
        );
        None
    }
}

/// Parse cross-compilation environment variables from `RUST_GNARK_GO_ENVS`.
///
/// Format: `"GOOS=ios;GOARCH=arm64;CC=/path/to/cc"`
/// Following SP1's `SP1_GNARK_FFI_GO_ENVS` pattern.
fn parse_go_envs() -> Vec<(String, String)> {
    let envs_str = env::var("RUST_GNARK_GO_ENVS").unwrap_or_default();
    if envs_str.is_empty() {
        return Vec::new();
    }

    envs_str
        .split(';')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Add platform-specific link directives for the Go runtime.
fn link_platform_deps(target: &str) {
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=resolv");
    } else if target.contains("android") {
        println!("cargo:rustc-link-lib=c");
        println!("cargo:rustc-link-lib=log");
    } else {
        // Linux and other Unix-like targets
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=resolv");
    }
}
