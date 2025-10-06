use std::path::Path;
use std::{env, fs};

use anyhow::{ensure, Context as _};

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=src/proto");

    let out_dir = env::var_os("OUT_DIR").context("failed to lookup `OUT_DIR`")?;
    let out_dir = Path::new(&out_dir);

    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);

    let file_descriptors = protox::compile(["src/proto/workload.proto"], ["src/proto"])
        .context("failed to compile protocol buffer file set")?;

    tonic_prost_build::configure()
        .build_client(true)
        .out_dir(out_dir)
        .compile_fds_with_config(file_descriptors, proto_config)
        .context("failed to compile protocol buffers")?;

    let workload = out_dir.join("_.rs");
    ensure!(
        workload.exists(),
        "expected generated file `_.rs` not found in `{}`",
        out_dir.display()
    );
    fs::rename(&workload, out_dir.join("workload.rs"))
        .with_context(|| format!("failed to rename `{}` to `workload.rs`", workload.display()))?;

    Ok(())
}
