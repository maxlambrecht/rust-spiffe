FUZZ_DIR := spiffe/fuzz
FUZZ_TARGETS := \
	fuzz_spiffe_id_parse \
	fuzz_trust_domain_parse

# Default fuzzing duration (seconds).
# Keep this short to preserve fast developer feedback.
#
# Override for deeper fuzzing:
#   FUZZ_SECONDS=300 make fuzz
#   FUZZ_SECONDS=1800 make fuzz
FUZZ_SECONDS ?= 60
FUZZ_MAX_LEN ?= 2048
FUZZ_DICT ?= fuzz.dict

.PHONY: fuzz-setup
fuzz-setup:
	@command -v cargo-fuzz >/dev/null 2>&1 || cargo +nightly install cargo-fuzz --locked

.PHONY: fuzz
fuzz: fuzz-setup
	@set -euo pipefail; \
	cd $(FUZZ_DIR); \
	for t in $(FUZZ_TARGETS); do \
	  echo "==> fuzz $$t ($(FUZZ_SECONDS)s, max_len=$(FUZZ_MAX_LEN), dict=$(FUZZ_DICT))"; \
	  cargo +nightly fuzz run $$t -- \
	    -max_total_time=$(FUZZ_SECONDS) \
	    -max_len=$(FUZZ_MAX_LEN) \
	    -dict=$(FUZZ_DICT); \
	done
