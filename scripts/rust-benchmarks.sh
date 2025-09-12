#!/bin/bash

# Script to run benchmarks with local guillotine build

# Get the directory of this script and then get the parent (repo root)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Build guillotine first
echo "Building guillotine..."
cd "$REPO_ROOT"
zig build || exit 1

# Build and run benchmarks with the local guillotine path
echo "Building benchmarks with local guillotine..."
cd "$REPO_ROOT/benchmarks"

# Set the GUILLOTINE_PATH to use the repo root directory
export GUILLOTINE_PATH="$REPO_ROOT"

# Build the benchmarks
cargo build --release || exit 1

echo "Running benchmarks..."
# Run benchmarks with the provided arguments or default to running all
if [ $# -eq 0 ]; then
    cargo run --release -- run --guillotine-path "$REPO_ROOT" --all
else
    cargo run --release -- "$@" --guillotine-path "$REPO_ROOT"
fi