# Releasing Crates

This repository uses a **tag-driven release workflow**.  
Crates are published automatically when a Git tag matching the crate name and version is pushed.

---

## 1. Prepare the release

- Choose the crate and new version.
- Update the crate’s `Cargo.toml` with the new version.
- Update `CHANGELOG.md` with release notes (features, fixes, notable changes).
- Update any relevant documentation (README, examples).

---

## 2. Open and merge the release PR

- Push the changes to a branch.
- Open a PR targeting `main` including:
    - version bump
    - changelog updates
    - documentation updates
- Ensure CI is green and merge the PR.

---

## 3. Create and push the release tag

After the PR is merged:

```sh
git checkout main
git pull
git tag CRATE-NAME-VERSION
git push origin CRATE-NAME-VERSION
````

**Important:**
The tag **must start with the crate name** for the publish workflow to trigger.

Example:

```sh
git tag spiffe-0.7.4
git push origin spiffe-0.7.4
```

---

## 4. GitHub release

* Go to **GitHub → Releases**
* Create a release from the tag
* Copy the notes from `CHANGELOG.md`
