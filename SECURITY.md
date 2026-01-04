# Security Policy

## Supported Versions

Only the latest released version is supported with security fixes.

## Reporting a Vulnerability

Please use GitHub’s Security Advisory reporting tool provided by the repository’s Security tab:
https://github.com/maxlambrecht/rust-spiffe/security/advisories/new

If you are unable to use GitHub Security Advisories, you may contact:
maxlambrecht@gmail.com

Please report issues as soon as possible. You do not need a proof of concept,
patch, or detailed write-up. A short description is sufficient to start the
process.

## Security Practices

This project follows standard Rust security best practices, including:

- No `unsafe` code (`#![deny(unsafe_code)]`)
- Dependency vulnerability scanning using `cargo-audit`
- Dependency, license, and source policy checks using `cargo-deny`
- Continuous integration checks on all pull requests

These practices are applied on a best-effort basis and are intended to reduce
risk, not to guarantee the absence of vulnerabilities.
