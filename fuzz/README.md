# Fuzz targets

libFuzzer harnesses for the parsers that consume network-sourced bytes. Requires nightly and
`cargo install cargo-fuzz`. The repo pins stable in rust-toolchain.toml, so pass `+nightly`.

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run dns_packet -- -max_total_time=60
cargo +nightly fuzz build            # compile every target without running
```

Crashes land in `fuzz/artifacts/<target>/`; reproduce with `cargo +nightly fuzz run <target> <artifact>`.
