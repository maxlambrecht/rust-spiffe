#![expect(missing_docs, reason = "xtask")]
#![expect(clippy::multiple_crate_versions, reason = "transitive")]

use anyhow::{bail, ensure, Context as _};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);

    match (args.next().as_deref(), args.next().as_deref(), args.next()) {
        (Some("gen"), Some("spiffe"), None) => gen_spiffe_protos(),
        (Some("gen"), Some("spire-api"), None) => gen_spire_api_protos(),
        (Some("-h" | "--help") | None, _, _) => {
            print_usage();
            Ok(())
        }
        (Some(cmd), Some(target), extra) => {
            if extra.is_some() {
                bail!("too many arguments\n\n{}", usage_text());
            }
            bail!("unknown command: {cmd} {target}\n\n{}", usage_text());
        }
        _ => bail!("{}", usage_text()),
    }
}

#[expect(clippy::print_stderr, reason = "sloppy CLI")]
fn print_usage() {
    eprintln!("{}", usage_text());
}

const fn usage_text() -> &'static str {
    "Usage:
  cargo run -p xtask -- gen spiffe
  cargo run -p xtask -- gen spire-api"
}

fn repo_root() -> anyhow::Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask must be in a workspace with a parent directory")
        .map(Path::to_path_buf)
}

fn gen_spiffe_protos() -> anyhow::Result<()> {
    let crate_dir = repo_root()?.join("spiffe");
    gen_spiffe_proto(
        &crate_dir,
        "workload.proto",
        "src/workload_api/pb",
        true,
        |_| {},
    )?;
    // The Broker Endpoint requires mTLS, so the broker client gets no plaintext `connect`.
    gen_spiffe_proto(
        &crate_dir,
        "broker.proto",
        "src/broker_api/pb",
        false,
        |config| {
            // Broker API references are packed into `google.protobuf.Any`, and SPIRE matches the
            // full type URL. The SVID messages hold a private key or a token, so they skip the
            // derived `Debug`. `spiffe::broker_api` implements one that shows only the length of
            // the key or token.
            config
                .enable_type_names()
                .type_name_domain(["."], "type.googleapis.com")
                .skip_debug([".spiffe.broker.X509SVID", ".spiffe.broker.JWTSVID"]);
        },
    )
}

#[expect(clippy::print_stdout, reason = "sloppy CLI")]
fn gen_spiffe_proto(
    crate_dir: &Path,
    proto_name: &str,
    out_dir: &str,
    transport: bool,
    configure: impl FnOnce(&mut prost_build::Config),
) -> anyhow::Result<()> {
    let proto_dir = crate_dir.join("src/proto");
    let proto_file = proto_dir.join(proto_name);

    ensure!(
        proto_file.exists(),
        "proto file not found: {}",
        proto_file.display()
    );

    // Committed output directory
    let out_dir = crate_dir.join(out_dir);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output dir: {}", out_dir.display()))?;

    // Generate into a clean temp dir to avoid stale files influencing selection
    let tmp_dir = out_dir.join(".tmp");
    reset_dir(&tmp_dir)?;

    compile_protos(
        &[proto_file],
        &proto_dir,
        &tmp_dir,
        transport,
        configure,
        &format!("failed to compile spiffe proto {proto_name}"),
    )?;

    // We expect exactly one generated .rs file for this invocation.
    let generated = single_generated_rs(&tmp_dir)?;
    let final_path = out_dir.join(Path::new(proto_name).with_extension("rs"));

    replace_file(&generated, &final_path)?;
    fs::remove_dir_all(&tmp_dir)
        .with_context(|| format!("failed to remove temp dir {}", tmp_dir.display()))?;

    try_rustfmt(&final_path, "2021", None);
    println!("Generated {}", final_path.display());
    Ok(())
}

#[expect(clippy::print_stdout, reason = "sloppy CLI")]
fn gen_spire_api_protos() -> anyhow::Result<()> {
    let repo_root = repo_root()?;

    let crate_dir = repo_root.join("spire-api");
    let proto_root = crate_dir.join("spire-api-sdk").join("proto");

    ensure!(
        proto_root.exists(),
        "spire-api-sdk submodule not found at {} (did you init/update it?)",
        proto_root.display()
    );

    let delegated = proto_root.join("spire/api/agent/delegatedidentity/v1/delegatedidentity.proto");
    ensure!(
        delegated.exists(),
        "proto file not found: {}",
        delegated.display()
    );

    let out_dir = crate_dir.join("src/pb");
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output dir: {}", out_dir.display()))?;

    let tmp_dir = out_dir.join(".tmp");
    reset_dir(&tmp_dir)?;

    compile_protos(
        &[delegated],
        &proto_root,
        &tmp_dir,
        true,
        |_| {},
        "failed to compile SPIRE delegated identity proto",
    )?;

    // SPIRE SDK generates multiple modules for imports (e.g., api/types).
    let expected = [
        "spire.api.agent.delegatedidentity.v1.rs",
        "spire.api.types.rs",
    ];

    for name in expected {
        let src = tmp_dir.join(name);
        ensure!(
            src.exists(),
            "expected generated file not found: {}",
            src.display()
        );

        let dst = out_dir.join(name);
        replace_file(&src, &dst)?;
        try_rustfmt(&dst, "2024", None);
        println!("Generated {}", dst.display());
    }

    fs::remove_dir_all(&tmp_dir)
        .with_context(|| format!("failed to remove temp dir {}", tmp_dir.display()))?;

    Ok(())
}

fn compile_protos(
    proto_files: &[PathBuf],
    include_dir: &Path,
    out_dir: &Path,
    transport: bool,
    configure: impl FnOnce(&mut prost_build::Config),
    err_ctx: &str,
) -> anyhow::Result<()> {
    let mut proto_config = prost_build::Config::new();
    proto_config.bytes(["."]);
    configure(&mut proto_config);

    let fds = protox::compile(proto_files.iter().map(PathBuf::as_path), [include_dir])
        .with_context(|| err_ctx.to_string())?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .build_transport(transport)
        .out_dir(out_dir)
        .compile_fds_with_config(fds, proto_config)
        .with_context(|| err_ctx.to_string())?;

    Ok(())
}

fn reset_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("failed to remove {}", dir.display()))?;
    }
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(())
}

fn single_generated_rs(dir: &Path) -> anyhow::Result<PathBuf> {
    let mut rs_files: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("failed to read dir {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension() == Some(OsStr::new("rs")))
        .collect();

    rs_files.sort();

    ensure!(
        rs_files.len() == 1,
        "expected exactly 1 generated .rs file in {}, found {}: {:?}",
        dir.display(),
        rs_files.len(),
        rs_files
    );

    Ok(rs_files.remove(0))
}

fn replace_file(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if dst.exists() {
        fs::remove_file(dst)
            .with_context(|| format!("failed removing existing {}", dst.display()))?;
    }

    fs::rename(src, dst).with_context(|| {
        format!(
            "failed to rename `{}` to `{}`",
            src.display(),
            dst.display()
        )
    })
}

fn try_rustfmt(path: &Path, edition: &str, config_path: Option<&Path>) {
    let mut cmd = Command::new("rustfmt");
    cmd.arg("--edition").arg(edition);

    if let Some(cfg) = config_path {
        cmd.arg("--config-path").arg(cfg);
    }

    let _unused: std::io::Result<std::process::ExitStatus> = cmd.arg(path).status();
}
