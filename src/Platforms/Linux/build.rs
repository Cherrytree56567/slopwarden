//! Links libclientwarden, which CMake builds; CW_LIB_DIR says where it is.

fn main() {
    println!("cargo:rerun-if-env-changed=CW_LIB_DIR");
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if let Ok(dir) = std::env::var("CW_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=dylib=clientwarden");
        if target == "macos" {
            // Development builds only: run against the library where CMake left it.
            println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        }
    }

    // The installed app keeps the library next to the executable.
    match target.as_str() {
        "linux" => println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN"),
        "macos" => println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path"),
        _ => {}
    }
}
