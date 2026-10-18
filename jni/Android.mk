# Android.mk  –  ndk-build script for linjector-cpp
#
# Usage (from the inject_c/ directory):
#   ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk
#
# Or place jni/Android.mk -> jni/Application.mk symlinks and run:
#   ndk-build
#
# Output lands in:
#   libs/<abi>/linjector-cli   – stripped executable
#   obj/local/<abi>/…          – unstripped objects

LOCAL_PATH := $(call my-dir)

# ============================================================
# Module 1: linjector_cpp  (static library)
# ============================================================
include $(CLEAR_VARS)

LOCAL_MODULE := linjector_cpp

LOCAL_SRC_FILES := \
    src/injector.cpp      \
    src/log.cpp           \
    src/remote_mem.cpp    \
    src/remote_module.cpp \
    src/remote_proc.cpp   \
    src/shellcode.cpp     \
    src/utils.cpp

LOCAL_C_INCLUDES    := $(LOCAL_PATH)/include
LOCAL_CPP_EXTENSION := .cpp

# C++20, exceptions enabled (InjectionException), RTTI on (dynamic_cast usage)
LOCAL_CPPFLAGS := \
    -std=c++20       \
    -fexceptions     \
    -frtti           \
    -Wall            \
    -Wextra          \
    -Os

# Strip dead code / data
LOCAL_CFLAGS := -ffunction-sections -fdata-sections
LOCAL_LDFLAGS := -Wl,--gc-sections

include $(BUILD_STATIC_LIBRARY)

# ============================================================
# Module 2: linjector-cli  (standalone executable)
# ============================================================
include $(CLEAR_VARS)

LOCAL_MODULE := linjector-cli

LOCAL_SRC_FILES  := src/main.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CPPFLAGS := \
    -std=c++20   \
    -fexceptions \
    -frtti       \
    -Os

LOCAL_CFLAGS  := -ffunction-sections -fdata-sections
LOCAL_LDFLAGS := -Wl,--gc-sections

LOCAL_STATIC_LIBRARIES := linjector_cpp

# Link against the system log library for Android logcat output.
LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)
