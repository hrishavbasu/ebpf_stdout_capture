use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/stdout_capture.bpf.c";

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    out.push("bpf_bindings.rs");

    println!("cargo:warning=Output file: {:?}", out);

    let clang_args = "-I/usr/include -I/usr/include/linux -I/usr/include/aarch64-linux-gnu";

    println!("cargo:warning=Clang args: {}", clang_args);

    let result = SkeletonBuilder::new()
        .source(SRC)
        .clang_args(clang_args)
        .build_and_generate(&out);

    match result {
        Ok(_) => println!("cargo:warning=SkeletonBuilder succeeded"),
        Err(err) => {
            println!("cargo:warning=Error in SkeletonBuilder: {:?}", err);
            panic!("Failed to build eBPF program");
        }
    }

    println!("cargo:rerun-if-changed={}", SRC);
}