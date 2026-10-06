#![expect(missing_docs, reason = "xtask")]
#![expect(clippy::multiple_crate_versions, reason = "transitive")]

use anyhow::{bail, ensure, Context as _};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.as_slice() {
        [cmd, target] if cmd == "gen" && target == "spiffe" => gen_spiffe_protos(),
        [cmd, target] if cmd == "gen" && target == "spire-api" => gen_spire_api_protos(),
        [cmd, action, rest @ ..] if cmd == "release" && action == "preflight" => {
            let args = ReleasePreflightArgs::parse(rest)?;
            let selected = release_preflight(&repo_root()?, &args)?;
            print_selected_crate(selected);
            Ok(())
        }
        [] => {
            print_usage();
            Ok(())
        }
        [cmd] if cmd == "-h" || cmd == "--help" => {
            print_usage();
            Ok(())
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
  cargo run -p xtask -- gen spire-api
  cargo run -p xtask -- release preflight <tag> --expected-commit <sha> [--main-ref <ref>]"
}

const DEFAULT_MAIN_REF: &str = "refs/remotes/origin/main";

#[derive(Debug, Eq, PartialEq)]
struct ReleasePreflightArgs {
    tag: String,
    expected_commit: String,
    main_ref: String,
}

impl ReleasePreflightArgs {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let [tag, options @ ..] = args else {
            bail!("{}", usage_text());
        };
        let mut expected_commit = None;
        let mut main_ref = None;
        let mut options = options.iter();
        while let Some(option) = options.next() {
            let slot = match option.as_str() {
                "--expected-commit" => &mut expected_commit,
                "--main-ref" => &mut main_ref,
                _ => bail!(
                    "unknown release preflight option `{option}`\n{}",
                    usage_text()
                ),
            };
            let value = options
                .next()
                .with_context(|| format!("missing value for `{option}`"))?;
            ensure!(slot.is_none(), "`{option}` given more than once");
            *slot = Some(value.clone());
        }

        let expected_commit = expected_commit.context("`--expected-commit <sha>` is required")?;
        ensure!(
            is_full_object_id(&expected_commit),
            "expected commit `{expected_commit}` must be a full lowercase hex object id"
        );
        let main_ref = main_ref.unwrap_or_else(|| DEFAULT_MAIN_REF.to_owned());
        // A fully qualified ref cannot be shadowed by a same-named tag or branch.
        ensure!(
            main_ref.starts_with("refs/"),
            "main ref `{main_ref}` must be fully qualified (for example, {DEFAULT_MAIN_REF})"
        );

        Ok(Self {
            tag: tag.clone(),
            expected_commit,
            main_ref,
        })
    }
}

fn is_full_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishedCrate {
    name: &'static str,
    manifest: &'static str,
}

const PUBLISHED_CRATES: &[PublishedCrate] = &[
    PublishedCrate {
        name: "spiffe",
        manifest: "spiffe/Cargo.toml",
    },
    PublishedCrate {
        name: "spire-api",
        manifest: "spire-api/Cargo.toml",
    },
    PublishedCrate {
        name: "spiffe-rustls",
        manifest: "spiffe-rustls/Cargo.toml",
    },
    PublishedCrate {
        name: "spiffe-rustls-tokio",
        manifest: "spiffe-rustls-tokio/Cargo.toml",
    },
];

#[expect(
    clippy::print_stdout,
    reason = "stdout is the machine-readable workflow output"
)]
fn print_selected_crate(selected: &PublishedCrate) {
    // Keep stdout machine-readable for the publishing workflow. Diagnostics go
    // through anyhow on stderr.
    println!("{}", selected.name);
}

fn release_preflight(
    root: &Path,
    args: &ReleasePreflightArgs,
) -> anyhow::Result<&'static PublishedCrate> {
    let versions = PUBLISHED_CRATES
        .iter()
        .map(|krate| {
            let manifest = root.join(krate.manifest);
            let (manifest_name, version) = read_package_identity(&manifest)?;
            ensure!(
                manifest_name == krate.name,
                "release catalog expects package `{}`, but {} declares `{manifest_name}`",
                krate.name,
                manifest.display()
            );
            Ok((*krate, version))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let selected = resolve_release_tag(&args.tag, &versions)?;
    validate_tag_commit(root, &args.tag, &args.main_ref, &args.expected_commit)?;
    PUBLISHED_CRATES
        .iter()
        .find(|krate| krate.name == selected.name)
        .context("selected crate is not in the release catalog")
}

fn read_package_identity(manifest: &Path) -> anyhow::Result<(String, String)> {
    let contents = fs::read_to_string(manifest)
        .with_context(|| format!("failed to read {}", manifest.display()))?;
    let mut in_package = false;
    let mut name = None;
    let mut version = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && line.starts_with('[') {
            break;
        }
        if !in_package || line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            continue;
        };
        match key.trim() {
            "name" => name = Some(value.to_owned()),
            "version" => version = Some(value.to_owned()),
            _ => {}
        }
    }

    let name =
        name.with_context(|| format!("{} has no literal package name", manifest.display()))?;
    let version = version
        .with_context(|| format!("{} has no literal package version", manifest.display()))?;
    Ok((name, version))
}

fn resolve_release_tag<'a>(
    tag: &str,
    versions: &'a [(PublishedCrate, String)],
) -> anyhow::Result<&'a PublishedCrate> {
    let matches = versions
        .iter()
        .filter(|(krate, version)| tag == format!("{}-{version}", krate.name))
        .collect::<Vec<_>>();

    if let [selected] = matches.as_slice() {
        return Ok(&selected.0);
    }

    if matches.len() > 1 {
        bail!("release tag `{tag}` maps to more than one publishable crate");
    }

    let mut names = versions.iter().collect::<Vec<_>>();
    names.sort_by_key(|(krate, _)| std::cmp::Reverse(krate.name.len()));
    if let Some((krate, version)) = names
        .into_iter()
        .find(|(krate, _)| tag.starts_with(&format!("{}-", krate.name)))
    {
        bail!(
            "release tag `{tag}` does not match {} version {version}; expected `{}-{version}`",
            krate.name,
            krate.name
        );
    }

    let namespaces = versions
        .iter()
        .map(|(krate, _)| format!("{}-<version>", krate.name))
        .collect::<Vec<_>>()
        .join(", ");
    bail!("release tag `{tag}` is not in a publishable namespace; expected one of: {namespaces}")
}

fn validate_tag_commit(
    root: &Path,
    tag: &str,
    main_ref: &str,
    expected_commit: &str,
) -> anyhow::Result<()> {
    ensure!(
        main_ref.starts_with("refs/"),
        "main ref `{main_ref}` must be fully qualified"
    );

    let tag_ref = format!("refs/tags/{tag}^{{commit}}");
    let main_commit_ref = format!("{main_ref}^{{commit}}");
    let tag_commit = git_output(root, ["rev-parse", "--verify", tag_ref.as_str()])
        .with_context(|| format!("release tag `{tag}` does not resolve to a commit"))?;
    let head_commit = git_output(root, ["rev-parse", "--verify", "HEAD^{commit}"])?;
    let main_commit = git_output(root, ["rev-parse", "--verify", main_commit_ref.as_str()])
        .with_context(|| format!("main ref `{main_ref}` does not resolve to a commit"))?;
    ensure!(
        head_commit == expected_commit,
        "checked-out commit {head_commit} is not the dispatch-selected commit {expected_commit}"
    );
    ensure!(
        tag_commit == head_commit,
        "release tag `{tag}` points to {tag_commit}, but the checked-out commit is {head_commit}"
    );
    ensure!(
        tag_commit == main_commit,
        "release tag `{tag}` points to {tag_commit}, but `{main_ref}` is {main_commit}; releases must use the current main tip"
    );

    git_output(root, ["ls-files", "--error-unmatch", "--", "Cargo.lock"])
        .context("root Cargo.lock is not tracked by git")?;
    let status = git_output(root, ["status", "--porcelain", "--untracked-files=all"])?;
    ensure!(
        status.is_empty(),
        "release validation requires a clean working tree; git status reported:\n{status}"
    );
    Ok(())
}

fn git_output<const N: usize>(root: &Path, args: [&str; N]) -> anyhow::Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .context("failed to execute git")?;
    ensure!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout)
        .context("git output was not UTF-8")
        .map(|s| s.trim().to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_REPO: AtomicUsize = AtomicUsize::new(0);

    struct TestRepo {
        path: PathBuf,
    }

    impl TestRepo {
        fn new() -> Self {
            let suffix = NEXT_REPO.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "rust-spiffe-release-test-{}-{suffix}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).unwrap();
            }
            fs::create_dir_all(&path).unwrap();

            let repo = Self { path };
            repo.git(["init", "--initial-branch=main"]);
            repo.git(["config", "user.name", "Release Test"]);
            repo.git(["config", "user.email", "release-test@example.invalid"]);
            repo.git(["config", "commit.gpgsign", "false"]);
            repo.git(["config", "tag.gpgsign", "false"]);
            for (krate, version) in versions() {
                let manifest = repo.path.join(krate.manifest);
                fs::create_dir_all(manifest.parent().unwrap()).unwrap();
                fs::write(
                    manifest,
                    format!(
                        "[package]\nname = \"{}\"\nversion = \"{version}\"\nedition.workspace = true\n\n[dependencies]\nversion = \"9.9.9\"\n",
                        krate.name
                    ),
                )
                .unwrap();
            }
            fs::write(repo.path.join("Cargo.lock"), "# committed lockfile\n").unwrap();
            fs::write(repo.path.join("tracked.txt"), "first\n").unwrap();
            repo.git(["add", "."]);
            repo.git(["commit", "-m", "first"]);
            repo
        }

        fn git<const N: usize>(&self, args: [&str; N]) -> String {
            git_output(&self.path, args).unwrap()
        }

        fn head(&self) -> String {
            self.git(["rev-parse", "HEAD"])
        }

        fn commit(&self, contents: &str) -> String {
            fs::write(self.path.join("tracked.txt"), contents).unwrap();
            self.git(["add", "tracked.txt"]);
            self.git(["commit", "-m", contents.trim()]);
            self.head()
        }

        /// Runs preflight the way the workflow does: the dispatch-selected
        /// commit is the checked-out commit and main is fully qualified.
        fn preflight(&self, tag: &str) -> anyhow::Result<&'static PublishedCrate> {
            self.preflight_expecting(tag, &self.head())
        }

        fn preflight_expecting(
            &self,
            tag: &str,
            expected_commit: &str,
        ) -> anyhow::Result<&'static PublishedCrate> {
            release_preflight(
                &self.path,
                &ReleasePreflightArgs {
                    tag: tag.to_owned(),
                    expected_commit: expected_commit.to_owned(),
                    main_ref: "refs/heads/main".to_owned(),
                },
            )
        }
    }

    fn assert_error_contains<T: std::fmt::Debug>(result: anyhow::Result<T>, needle: &str) {
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains(needle), "expected `{needle}` in: {error}");
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|&v| v.to_owned()).collect()
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    impl Drop for TestRepo {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    fn versions() -> Vec<(PublishedCrate, String)> {
        vec![
            (
                PublishedCrate {
                    name: "spiffe",
                    manifest: "spiffe/Cargo.toml",
                },
                "0.17.0".into(),
            ),
            (
                PublishedCrate {
                    name: "spire-api",
                    manifest: "spire-api/Cargo.toml",
                },
                "0.9.0".into(),
            ),
            (
                PublishedCrate {
                    name: "spiffe-rustls",
                    manifest: "spiffe-rustls/Cargo.toml",
                },
                "0.9.0".into(),
            ),
            (
                PublishedCrate {
                    name: "spiffe-rustls-tokio",
                    manifest: "spiffe-rustls-tokio/Cargo.toml",
                },
                "0.5.0".into(),
            ),
        ]
    }

    #[test]
    fn release_tag_resolves_each_published_crate_without_prefix_ambiguity() {
        let versions = versions();
        for (expected, version) in &versions {
            let tag = format!("{}-{version}", expected.name);
            let actual = resolve_release_tag(&tag, &versions).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn release_tag_rejects_manifest_version_mismatch() {
        let versions = versions();
        let error = resolve_release_tag("spiffe-0.17.1", &versions).unwrap_err();
        assert!(
            error.to_string().contains("expected `spiffe-0.17.0`"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn release_tag_rejects_malformed_and_unknown_namespaces() {
        let versions = versions();
        for tag in [
            "spiffe-v0.17.0",
            "spiffe-0.17",
            "v0.17.0",
            "unrelated-1.0.0",
        ] {
            assert!(
                resolve_release_tag(tag, &versions).is_err(),
                "tag should have been rejected: {tag}"
            );
        }
    }

    #[test]
    fn preflight_selects_each_crate_at_current_main_tip() {
        let repo = TestRepo::new();
        for (krate, version) in versions() {
            let tag = format!("{}-{version}", krate.name);
            repo.git(["tag", "-a", tag.as_str(), "-m", tag.as_str()]);

            let selected = repo.preflight(&tag).unwrap();
            assert_eq!(selected.name, krate.name);
            assert_eq!(selected.manifest, krate.manifest);
        }
    }

    #[test]
    fn preflight_rejects_malformed_tags_even_when_they_exist() {
        let repo = TestRepo::new();
        for tag in [
            "spiffe-v0.17.0",
            "spiffe-0.17",
            "spiffe-0.17.0-",
            "spiffe_0.17.0",
            "Spiffe-0.17.0",
            "-spiffe-0.17.0",
            "refs/tags/spiffe-0.17.0",
            "v0.17.0",
        ] {
            let _created = git_output(&repo.path, ["tag", tag]);
            assert!(
                repo.preflight(tag).is_err(),
                "tag should have been rejected: {tag}"
            );
        }
        assert_error_contains(repo.preflight(""), "not in a publishable namespace");
    }

    #[test]
    fn preflight_rejects_unknown_crate_namespace() {
        let repo = TestRepo::new();
        repo.git(["tag", "spire-server-0.9.0"]);

        assert_error_contains(
            repo.preflight("spire-server-0.9.0"),
            "not in a publishable namespace",
        );
    }

    #[test]
    fn preflight_rejects_manifest_version_mismatch() {
        let repo = TestRepo::new();
        for tag in [
            "spiffe-0.18.0",
            "spiffe-rustls-0.5.0",
            "spiffe-rustls-tokio-0.9.0",
        ] {
            repo.git(["tag", tag]);
            assert_error_contains(repo.preflight(tag), "does not match");
        }
    }

    #[test]
    fn preflight_ignores_version_keys_outside_package_table() {
        let repo = TestRepo::new();
        repo.git(["tag", "spiffe-9.9.9"]);

        assert_error_contains(repo.preflight("spiffe-9.9.9"), "expected `spiffe-0.17.0`");
    }

    #[test]
    fn preflight_rejects_missing_tag() {
        let repo = TestRepo::new();

        assert_error_contains(
            repo.preflight("spiffe-0.17.0"),
            "does not resolve to a commit",
        );
    }

    #[test]
    fn preflight_rejects_tag_not_at_checked_out_commit() {
        let repo = TestRepo::new();
        repo.git(["tag", "spiffe-0.17.0"]);
        repo.commit("second\n");

        assert_error_contains(repo.preflight("spiffe-0.17.0"), "checked-out commit");
    }

    #[test]
    fn preflight_rejects_checkout_that_is_not_the_dispatch_commit() {
        let repo = TestRepo::new();
        let first = repo.head();
        repo.commit("second\n");
        repo.git(["tag", "spiffe-0.17.0"]);

        assert_error_contains(
            repo.preflight_expecting("spiffe-0.17.0", &first),
            "dispatch-selected commit",
        );
        assert_error_contains(
            repo.preflight_expecting("spiffe-0.17.0", SHA),
            "dispatch-selected commit",
        );
    }

    #[test]
    fn preflight_rejects_non_main_commit() {
        let repo = TestRepo::new();
        repo.git(["switch", "-c", "release"]);
        repo.commit("release branch\n");
        repo.git(["tag", "spiffe-0.17.0"]);

        assert_error_contains(repo.preflight("spiffe-0.17.0"), "current main tip");
    }

    #[test]
    fn preflight_rejects_old_main_ancestor() {
        let repo = TestRepo::new();
        let old_main = repo.head();
        repo.git(["tag", "spiffe-0.17.0"]);
        repo.commit("new main tip\n");
        repo.git(["switch", "--detach", old_main.as_str()]);

        assert_error_contains(repo.preflight("spiffe-0.17.0"), "current main tip");
    }

    #[test]
    fn preflight_rejects_modified_tracked_files_and_lockfile() {
        let repo = TestRepo::new();
        repo.git(["tag", "spiffe-0.17.0"]);
        fs::write(repo.path.join("tracked.txt"), "dirty\n").unwrap();
        assert_error_contains(repo.preflight("spiffe-0.17.0"), "tracked.txt");

        repo.git(["checkout", "--", "tracked.txt"]);
        fs::write(repo.path.join("Cargo.lock"), "# modified lockfile\n").unwrap();
        assert_error_contains(repo.preflight("spiffe-0.17.0"), "Cargo.lock");
    }

    #[test]
    fn preflight_rejects_untracked_files() {
        let repo = TestRepo::new();
        repo.git(["tag", "spiffe-0.17.0"]);
        fs::write(repo.path.join("untracked.txt"), "dirty\n").unwrap();

        assert_error_contains(repo.preflight("spiffe-0.17.0"), "untracked.txt");
    }

    #[test]
    fn preflight_rejects_untracked_lockfile() {
        let repo = TestRepo::new();
        repo.git(["rm", "--cached", "--quiet", "Cargo.lock"]);
        repo.git(["commit", "-m", "untrack lockfile"]);
        repo.git(["tag", "spiffe-0.17.0"]);

        assert_error_contains(repo.preflight("spiffe-0.17.0"), "Cargo.lock is not tracked");
    }

    #[test]
    fn preflight_args_require_full_expected_commit() {
        let parsed =
            ReleasePreflightArgs::parse(&args(&["spiffe-0.17.0", "--expected-commit", SHA]))
                .unwrap();
        assert_eq!(
            parsed,
            ReleasePreflightArgs {
                tag: "spiffe-0.17.0".to_owned(),
                expected_commit: SHA.to_owned(),
                main_ref: DEFAULT_MAIN_REF.to_owned(),
            }
        );

        assert_error_contains(
            ReleasePreflightArgs::parse(&args(&["spiffe-0.17.0"])),
            "--expected-commit <sha>` is required",
        );
        for bad in [
            "0123456",
            &SHA.to_uppercase(),
            "HEAD",
            "-0123456789abcdef0123456789abcdef0123456",
        ] {
            assert_error_contains(
                ReleasePreflightArgs::parse(&args(&["spiffe-0.17.0", "--expected-commit", bad])),
                "full lowercase hex object id",
            );
        }
    }

    #[test]
    fn preflight_args_require_fully_qualified_main_ref() {
        for bad in ["origin/main", "main", "-main", "--all"] {
            assert_error_contains(
                ReleasePreflightArgs::parse(&args(&[
                    "spiffe-0.17.0",
                    "--expected-commit",
                    SHA,
                    "--main-ref",
                    bad,
                ])),
                "must be fully qualified",
            );
        }
    }

    #[test]
    fn preflight_args_reject_unknown_duplicate_and_incomplete_options() {
        let cases: [(&[&str], &str); 4] = [
            (
                &["spiffe-0.17.0", "--expected-commit", SHA, "--force"],
                "unknown",
            ),
            (
                &[
                    "spiffe-0.17.0",
                    "--expected-commit",
                    SHA,
                    "--expected-commit",
                    SHA,
                ],
                "more than once",
            ),
            (&["spiffe-0.17.0", "--expected-commit"], "missing value"),
            (&[], "Usage"),
        ];
        for (input, needle) in cases {
            assert_error_contains(ReleasePreflightArgs::parse(&args(input)), needle);
        }
    }
}
