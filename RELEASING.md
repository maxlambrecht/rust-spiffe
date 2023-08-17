# Releasing Crates

Follow these steps to create a new release for a specific crate in the repository.

## 1. Prepare the Release

- Determine the crate you are releasing and the new version number.
- Update the crate's `Cargo.toml` file with the new version number on a dedicated branch.
- Update the CHANGELOG.md file with detailed notes about the new release. Include any new features, bug fixes, and other
  relevant information.
- Update any relevant documentation, including README files and any public-facing documents related to the crate.

## 2. Create a Pull Request (PR) for Preparing the Release

- Push the branch and create a pull request to merge the changes into the main branch.
- Include the changes to the `Cargo.toml`, CHANGELOG.md, and documentation files in the PR.
- Engage the maintainers for a thorough review of the changes.

## 3. Merge the PR

- Once the PR is approved, merge it into the main branch.

## 4. Create the Release Branch

- Checkout the main branch.
- Create a new branch for the release, named with the pattern `release/CRATE-NAME-VERSION`.

For example:
```sh
git checkout -b release/spiffe-v0.3.2
```

## 5. Create a Git Tag

- Create a Git tag for the new release, using the same pattern `CRATE-NAME-VERSION`.

For example:
```sh
git tag spiffe-v0.3.2
```

- Push the tag and the branch to the repository.

## 6. Publish the Crate

For example:
```sh
cargo publish --manifest-path spiffe/Cargo.toml
```

## 7 Create a GitHub Release

Navigate to the "Releases" section in the repository on GitHub.
Draft a new release using the tag created earlier, and include the notes from the CHANGELOG.md.
Publish the release.