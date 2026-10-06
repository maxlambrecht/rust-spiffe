# Releasing crates

Publishing is manual and uses crates.io Trusted Publishing. Pushing a release
tag does not publish it.

## Prepare the release

1. Update the crate version in `Cargo.toml` and update `CHANGELOG.md`.
2. Update dependent crate requirements or documentation if needed.
3. From a clean commit, run:

   ```sh
   make release-check CRATE=spiffe
   ```

Valid crate names:

- `spiffe`
- `spire-api`
- `spiffe-rustls`
- `spiffe-rustls-tokio`

4. Open a release PR against `main`, obtain review, require green CI, and merge it.

Do not tag an unreviewed branch.

## Tag the release

After the release commit is the current `main` tip:

```sh
git checkout main
git pull --ff-only
git tag -a spiffe-0.18.0 -m "spiffe 0.18.0"
git push origin spiffe-0.18.0
```

Valid tag formats:

- `spiffe-VERSION`
- `spire-api-VERSION`
- `spiffe-rustls-VERSION`
- `spiffe-rustls-tokio-VERSION`

Do not move or reuse release tags.

## Publish

In GitHub:

1. Open **Actions → Publish Crates → Run workflow**.
2. Select branch **main**.
3. Enter the existing release tag.
4. Run the workflow.
5. Approve the `crates-io` environment deployment if prompted.

The workflow verifies that the tag matches the crate version and points to the
current `main` tip, runs the release checks, verifies the packaged crate, and
publishes through crates.io Trusted Publishing.

After publishing succeeds, create the GitHub release from the tag using the
reviewed changelog notes.

## If publishing fails

Fix the release on `main` and create a new release tag.

Do not move, overwrite, or reuse an existing protected or published tag.