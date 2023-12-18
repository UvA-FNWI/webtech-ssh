#!/bin/sh
# build wrapper which builds linux targets on linux, macos targets on macos

platform=$(uname)

case "$platform" in
    "Linux")
        CARGO_BUILD_TARGET=aarch64-unknown-linux-musl cargo build "$@"
        CARGO_BUILD_TARGET=x86_64-unknown-linux-musl cargo build "$@"
        ;;
    "Darwin")
        CARGO_BUILD_TARGET=aarch64-apple-darwin cargo build "$@"
        CARGO_BUILD_TARGET=x86_64-apple-darwin cargo build "$@"
        ;;
esac
