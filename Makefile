.PHONY: switch-rs
ARCH?=x86_64
all: switch-rs

switch-rs: ebpf
	(cd switch-rs;cargo build --release --target=${ARCH}-unknown-linux-gnu)
ebpf:
	(cargo xtask build-ebpf --release)