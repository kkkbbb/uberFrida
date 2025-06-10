frida-rust
==========

Rust bindings for [Frida](http://www.frida.re/).

## Install

- Build Frida, or download the devkits for your system (see `frida-gum` or `frida-core` README for version)
- For crate installation:
    - Move the frida-gum and frida-core devkits into `rustc-link-search`, e.g.: `/usr/local/{include, lib}` on Unix
- For local development:
    - Move the frida-gum devkit into `frida-gum-sys`, and the frida-core devkit into `frida-sys` and `cargo build` in the root
## Build for Android
- 打开 设置-Rust
- 设置环境变量：CC=D:/androidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd;BINDGEN_EXTRA_CLANG_ARGS=--sysroot=D:\\androidSdk\\ndk\\28.0.13004108\\toolchains\\llvm\\prebuilt\\windows-x86_64\\sysroot;CFLAGS=--sysroot=D:/androidSdk/ndk/28.0.13004108/toolchains/llvm/prebuilt/windows-x86_64/sysroot