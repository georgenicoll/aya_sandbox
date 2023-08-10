# helloxdp

See https://aya-rs.dev/book/start/

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

# aya-tool

See https://aya-rs.dev/book/aya/aya-tool/

```bash
cargo install bindgen-cli
cargo install --git https://github.com/aya-rs/aya -- aya-tool
```
