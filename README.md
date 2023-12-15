# webtech-ssh
`webtech-ssh` is the client component of the automated webtech SSH provisioning.
The server component can be found [here](https://github.com/UvA-FNWI/webtech-admin).

# Building
As usual, we use `cargo` for builds. We build for four targets:

- aarch64-apple-darwin (ARM macOS)
- x86_64-apple-darwin  (Intel macOS)

- aarch64-unknown-linux-musl (ARM Linux)
- x86_64-unknown-linux-musl  (x64 Linux)

The Linux musl builds require a few dependencies to be installed; on Arch these are:

- musl
- aarch64-linux-musl (AUR)

To build the targets appropriate for your host platform, run `build.sh`. This will
build the macOS targets on macOS and the Linux targets on Linux.

In theory, we might want to cross-compile the macOS targets from Linux, but this
seems to be a fairly finicky affair, and there is a Mac available for building, so
this is not currently a priority.

# Usage
Simply run `webtech-ssh`; it will do the rest automatically.
