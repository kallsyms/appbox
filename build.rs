use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let sdkroot_bytes = Command::new("xcrun")
        .arg("--sdk")
        .arg("macosx")
        .arg("--show-sdk-path")
        .output()
        .expect("failed to get sdkroot")
        .stdout;
    //let sdkroot = PathBuf::from(String::from_utf8_lossy(&sdkroot_bytes).trim());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("src/third_party/dyld_cache_format.h")
        .generate()
        .expect("Unable to generate dyld bindings")
        .write_to_file(out_dir.join("dyld_cache_format.rs"))
        .expect("Couldn't write dyld bindings");
}
