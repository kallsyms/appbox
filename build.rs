use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindgen::Builder::default()
        .header("src/third_party/dyld_cache_format.h")
        .generate()
        .expect("Unable to generate dyld bindings")
        .write_to_file(out_dir.join("dyld_cache_format.rs"))
        .expect("Couldn't write dyld bindings");

    bindgen::Builder::default()
        .header("src/third_party/cpu_capabilities.h")
        .generate()
        .expect("Unable to generate commpage/cpu_capabilities bindings")
        .write_to_file(out_dir.join("commpage.rs"))
        .expect("Couldn't write commpage/cpu_capabilities bindings");
}
