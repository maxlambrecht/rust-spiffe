#!/usr/bin/env bash
set -euo pipefail

# Filter an LCOV file so that only records whose source file lives under */src/**
# are kept. This ensures coverage reflects only hand-written library code.
#
# Usage:
#   ./filter-lcov.sh [lcov_file]
#
# Defaults to "lcov.info" if no argument is provided.

input_file="${1:-lcov.info}"
tmp_file="${input_file}.tmp"

if [[ ! -f "$input_file" ]]; then
  echo "Error: LCOV file not found: $input_file" >&2
  exit 1
fi

keep=0

# LCOV format:
#   - Each record starts with: SF:<absolute-or-relative-path>
#   - Each record ends with:   end_of_record
#
# We stream the file and drop entire records that do not match */src/**.
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" == SF:* ]]; then
    file="${line#SF:}"

    # Keep only files where "src" is a path segment (*/src/**)
    if [[ "$file" == */src/* ]]; then
      keep=1
      printf '%s\n' "$line"
    else
      keep=0
    fi

    continue
  fi

  if [[ $keep -eq 1 ]]; then
    printf '%s\n' "$line"
  fi

  if [[ "$line" == "end_of_record" ]]; then
    keep=0
  fi
done < "$input_file" > "$tmp_file"

mv "$tmp_file" "$input_file"
