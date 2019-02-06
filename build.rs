use std::env;
use std::process::Command;
use std::str;

fn main() {

    let rustc_minor_ver
        = rustc_minor_version().expect("Failed to get rustc version");
    let rustc_dep_of_std
        = std::env::var("CARGO_FEATURE_RUSTC_DEP_OF_STD").is_ok();
    let align_cargo_feature
        = std::env::var("CARGO_FEATURE_ALIGN").is_ok();

    // Rust >= 1.19 supports unions:
    if rustc_minor_ver >= 19 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_union");
    }

    // Rust >= 1.24 supports const mem::size_of:
    if rustc_minor_ver >= 24 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_const_size_of");
    }

    // Rust >= 1.25 supports repr(align):
    if rustc_minor_ver >= 25 || rustc_dep_of_std || align_cargo_feature {
        println!("cargo:rustc-cfg=libc_align");
    }

    // If `core::ffi::c_void` exists, libc can just re-export it. Otherwise, it
    // must define an incompatible type to retain backwards-compatibility.
    if rustc_minor_ver >= 30 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_core_cvoid");
    }

    // Rust >= 1.33 supports repr(packed(N))
    if rustc_minor_ver >= 30 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_packedN");
    }
}

fn rustc_minor_version() -> Option<u32> {
    macro_rules! otry {
        ($e:expr) => {
            match $e {
                Some(e) => e,
                None => return None,
            }
        };
    }

    let rustc = otry!(env::var_os("RUSTC"));
    let output = otry!(Command::new(rustc).arg("--version").output().ok());
    let version = otry!(str::from_utf8(&output.stdout).ok());
    let mut pieces = version.split('.');

    if pieces.next() != Some("rustc 1") {
        return None;
    }

    otry!(pieces.next()).parse().ok()
}
