#!/bin/sh

set -e
set -o xtrace

cargo build --lib --release
cargo build --bin insject --release
python3 patch.py target/release/insject
