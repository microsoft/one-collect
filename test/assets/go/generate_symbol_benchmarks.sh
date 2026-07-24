#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -euo pipefail

readonly expected_version="go1.23.4"
readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly go_binary="${GO:-go}"
readonly source_file="${script_dir}/symbol_benchmark.go"
readonly common_flags=(
    -buildvcs=false
    -trimpath
)

actual_version="$("${go_binary}" version | awk '{print $3}')"
if [[ "${actual_version}" != "${expected_version}" ]]; then
    echo "expected ${expected_version}, found ${actual_version}" >&2
    exit 1
fi

export CGO_ENABLED=0
export GOARCH=amd64
export GOOS=linux

"${go_binary}" build \
    "${common_flags[@]}" \
    -ldflags="-buildid= -w" \
    -o "${script_dir}/symbol_benchmark_elf" \
    "${source_file}"

"${go_binary}" build \
    "${common_flags[@]}" \
    -ldflags="-buildid= -s -w" \
    -o "${script_dir}/symbol_benchmark_go" \
    "${source_file}"
