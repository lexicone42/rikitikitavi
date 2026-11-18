#!/usr/bin/env bash
# Line coverage of the committed corpora, per parser/classifier function.
# Needs nightly with llvm-tools, cargo-fuzz, rustfilt and uv. Run from the repo root.
set -euo pipefail

bin_dir=$(dirname "$(find "$(rustc +nightly --print sysroot)" -name llvm-cov -type f | head -1)")
triple=$(rustc +nightly -vV | sed -n 's/^host: //p')
build="target/$triple/coverage/$triple/release"
targets=$(cargo +nightly fuzz list)

for t in $targets; do
    cargo +nightly fuzz coverage "$t" >/dev/null 2>&1
done
"$bin_dir/llvm-profdata" merge -sparse fuzz/coverage/*/coverage.profdata -o fuzz/coverage/all.profdata

objects=()
for t in $targets; do objects+=(-object "$build/$t"); done
sources=$(ls crates/rikitikitavi-scanners/src/*.rs crates/rikitikitavi-scanners/src/mdns/*.rs \
    crates/rikitikitavi-network/src/*.rs | grep -v _db)
# shellcheck disable=SC2086
"$bin_dir/llvm-cov" report "${objects[1]}" "${objects[@]:2}" -instr-profile=fuzz/coverage/all.profdata \
    -show-functions -Xdemangler=rustfilt $sources 2>/dev/null |
    uv run --no-project python fuzz/coverage_summary.py
