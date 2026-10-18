# Application.mk  –  global ndk-build settings for linjector-cpp
#
# Only AArch64 is supported (mirrors the Rust implementation which targets
# aarch64 exclusively – the shellcode is hand-encoded AArch64).

# Target ABI
APP_ABI := arm64-v8a

# C++ Standard Library – static so the resulting binary is self-contained
# and can be pushed to /data/local/tmp on any Android device without
# installing libc++_shared.so separately.
APP_STL := c++_static

# Minimum API level.
# - API 26 (Android 8.0): first level where std::filesystem is fully usable
#   with libc++ on AArch64.
# - API 23 is sufficient if filesystem calls are avoided, but utils.cpp uses
#   std::filesystem::canonical / copy_file / directory_iterator.
APP_PLATFORM := android-26

# Release build: size-optimised, no debug info, LTO (mirrors Cargo release
# profile: opt-level = "z", lto = true, strip = true).
APP_OPTIM := release

# Enable C++20 globally (each module still passes -std=c++20 via LOCAL_CPPFLAGS
# for explicitness, but this ensures the NDK toolchain is configured correctly).
APP_CPPFLAGS := -std=c++20 -fexceptions -frtti

# Strip symbols from installed binaries (equivalent to Rust's strip = true).
APP_STRIP_MODE := --strip-all
