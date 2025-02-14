use std::path::Path;
use std::{env, fs};

use anyhow::{bail, Context as _};

fn main() -> anyhow::Result<()> {
    // Check if this is a docs.rs build
    let is_docs_rs = env::var_os("DOCS_RS").is_some();

    if !is_docs_rs {
        let mut proto_config = prost_build::Config::new();
        proto_config.bytes(["."]);
        let out_dir = env::var_os("OUT_DIR").context("failed to lookup `OUT_DIR`")?;
        let out_dir = Path::new(&out_dir);
        let proto_dir = Path::new("src/proto");
        let file_descriptors = protox::compile([proto_dir.join("workload.proto")], [proto_dir])
            .context("failed to compile protocol buffer file set")?;
        tonic_build::configure()
            .build_client(true)
            .out_dir(out_dir)
            .compile_fds_with_config(proto_config, file_descriptors)
            .context("failed to compile protocol buffers")?;
        for entry in fs::read_dir(out_dir).context("failed to read OUT_DIR")? {
            let entry = entry.context("failed to get entry")?;
            let ty = entry.file_type().context("failed to get file type")?;
            let path = entry.path();
            if ty.is_file() {
                let buf = fs::read(&path).with_context(|| {
                    format!("failed to read generated file at `{}`", path.display())
                })?;
                let name = entry.file_name();
                let target = match name.to_str() {
                    Some("_.rs") => proto_dir.join("workload.rs"),
                    _ => proto_dir.join(name),
                };
                if let Ok(got) = fs::read(&target) {
                    if got == buf {
                        continue;
                    }
                }
                fs::rename(&path, &target).with_context(|| {
                    format!(
                        "failed to move `{}` to `{}`",
                        path.display(),
                        target.display()
                    )
                })?;
            } else {
                bail!(
                    "unexpected file type generated at `{}`: {ty:?}",
                    path.display()
                )
            }
        }
    } else {
        println!("cargo:warning=Skipping protobuf code generation on docs.rs.");
    }

    Ok(())
}
