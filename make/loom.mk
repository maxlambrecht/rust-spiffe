# -----------------------------------------------------------------------------
# Loom protocol models (loom-tests; see loom-tests/README.md)
# -----------------------------------------------------------------------------
# Standalone crate with its own workspace boundary and committed Cargo.lock.
# It never touches the root workspace, its lockfile, or its dependency checks.
#
# Canonical settings use := so inherited environment variables cannot weaken
# them. Override deliberately on the command line, for example:
#   make loom LOOM_PREEMPTION_BOUND=4
# Exact interleaving counts are enforced only at the canonical bound (3).
LOOM_MANIFEST := loom-tests/Cargo.toml
LOOM_PREEMPTION_BOUND := 3
LOOM_TIMEOUT_SECS := 300
LOOM_SCENARIOS := 2

# Every model variant and its expected outcome is defined in
# loom-tests/tests/tls_revision_gating.rs (`expected`). A variant passes only
# when each scenario meets that expectation: complete exploration for baseline
# and variant-*, detection for the expected reason for defect-*.
LOOM_VARIANTS := \
	baseline \
	variant-source-first \
	variant-torn-revision-first \
	defect-torn-observe \
	defect-no-revision-gate \
	defect-gate-applied-revision \
	defect-notify-before-store \
	defect-observe-before-subscribe

# Shell fragment: map $$variant to cargo feature flags in $$features.
LOOM_FEATURES = features=; if [ "$${variant}" != baseline ]; then features="--features $${variant}"; fi

.PHONY: loom loom-lint loom-test
loom: loom-lint loom-test

loom-lint:
	$(CARGO) fmt --manifest-path $(LOOM_MANIFEST) --check
	@set -euo pipefail; \
	for variant in $(LOOM_VARIANTS); do \
		$(LOOM_FEATURES); \
		printf '%s\n' "==> loom clippy: $${variant}"; \
		$(CARGO) clippy $(LOCKED) --manifest-path $(LOOM_MANIFEST) --all-targets $${features} -- -D warnings; \
	done

loom-test:
	@set -euo pipefail; \
	for variant in $(LOOM_VARIANTS); do \
		$(LOOM_FEATURES); \
		printf '%s\n' "==> loom: $${variant} (preemption bound $(LOOM_PREEMPTION_BOUND))"; \
		status=0; \
		output="$$(SPIFFE_LOOM_PREEMPTION_BOUND='$(LOOM_PREEMPTION_BOUND)' \
			SPIFFE_LOOM_TIMEOUT_SECS='$(LOOM_TIMEOUT_SECS)' \
			$(CARGO) test $(LOCKED) --manifest-path $(LOOM_MANIFEST) $${features} \
			--test tls_revision_gating -- --test-threads=1 --nocapture 2>&1)" || status=$$?; \
		printf '%s\n' "$${output}"; \
		if [ "$${status}" -ne 0 ]; then \
			printf '%s\n' "error: loom $${variant}: test run failed (exit $${status})" >&2; \
			exit 1; \
		fi; \
		if ! grep -Eq '^test result: ok\. $(LOOM_SCENARIOS) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' <<<"$${output}"; then \
			printf '%s\n' "error: loom $${variant}: expected exactly $(LOOM_SCENARIOS) scenarios to run and pass" >&2; \
			exit 1; \
		fi; \
	done; \
	printf '%s\n' "==> loom: all $(words $(LOOM_VARIANTS)) variants met their expected outcomes"
