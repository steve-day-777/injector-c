#!/bin/bash
NDK_PATH="/home/giao/AndroidDevelope/NDK/r27d/android-ndk-r27d"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$NDK_PATH/ndk-build" NDK_PROJECT_PATH="$SCRIPT_DIR" NDK_APPLICATION_MK="$SCRIPT_DIR/jni/Application.mk" -j$(nproc) "$@"
