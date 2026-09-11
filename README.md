# unipe

AI-based detection of cyber threats in unidirectional IP traffic.

- `unipe-ebpf` — XDP program that counts flows in an LRU map.
- `unipe` — userspace exporter; snapshots the map and publishes flow records
  over a Unix socket.
- `unipe-ai` — Python detection engine. See [unipe-ai/README.md](unipe-ai/README.md)
  for the models, features, training/validation, throughput and alert schema.

The tap is one-way by design: the exporter only reads, the engine only reads the
socket, and no component can send anything back toward the monitored network.

```shell
sudo cargo run --release -p unipe -- --iface eth0 --interval-ms 250
cd unipe-ai && python3 run.py --alerts-out alerts.jsonl
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package unipe --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/unipe` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, unipe is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
