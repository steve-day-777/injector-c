#pragma once
// log.hpp  –  Lightweight logging for linjector-cpp.
//
// Mirrors the Rust log/simple_logger/android_logger combination used in the
// original implementation.  Four levels are supported:
//
//   LLOG_DEBUG(fmt, ...)   – verbose, off by default
//   LLOG_INFO(fmt, ...)    – normal progress messages
//   LLOG_WARN(fmt, ...)    – non-fatal anomalies
//   LLOG_ERROR(fmt, ...)   – fatal errors (still thrown as exceptions)
//
// On Android the messages are also sent to logcat with tag "linjector".
// On any platform they are always written to stderr.
//
// Call linjector::log::set_level(Level::Debug) to enable debug output
// (corresponds to --debug in the CLI).

#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef __ANDROID__
#  include <android/log.h>
#  define LINJECTOR_LOG_TAG "linjector"
#endif

namespace linjector::log {

enum class Level : int {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
};

// Minimum level to emit; set via set_level().
extern Level g_min_level;

inline void set_level(Level lv) noexcept { g_min_level = lv; }
inline Level get_level() noexcept        { return g_min_level; }

namespace detail {

inline const char* level_tag(Level lv) noexcept {
    switch (lv) {
    case Level::Debug: return "DEBUG";
    case Level::Info:  return "INFO ";
    case Level::Warn:  return "WARN ";
    case Level::Error: return "ERROR";
    default:           return "?    ";
    }
}

// Core emit function – not for direct use; call the macros below.
inline void emit(Level lv, const char* fmt, va_list ap) noexcept {
    if (lv < g_min_level) return;

    char msg[2048];
    vsnprintf(msg, sizeof(msg), fmt, ap);

#ifdef __ANDROID__
    int android_prio = ANDROID_LOG_DEFAULT;
    switch (lv) {
    case Level::Debug: android_prio = ANDROID_LOG_DEBUG; break;
    case Level::Info:  android_prio = ANDROID_LOG_INFO;  break;
    case Level::Warn:  android_prio = ANDROID_LOG_WARN;  break;
    case Level::Error: android_prio = ANDROID_LOG_ERROR; break;
    default: break;
    }
    __android_log_print(android_prio, LINJECTOR_LOG_TAG, "%s", msg);
#endif

    // stderr output (always) – format: "[LEVEL] message\n"
    fprintf(stderr, "[%s] %s\n", level_tag(lv), msg);
}

inline void log_impl(Level lv, const char* fmt, ...) noexcept {
    va_list ap;
    va_start(ap, fmt);
    emit(lv, fmt, ap);
    va_end(ap);
}

} // namespace detail
} // namespace linjector::log

// ---------------------------------------------------------------------------
// Public macros  –  use these everywhere
// ---------------------------------------------------------------------------

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LLOG_DEBUG(fmt, ...) \
    ::linjector::log::detail::log_impl(::linjector::log::Level::Debug, fmt, ##__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LLOG_INFO(fmt, ...) \
    ::linjector::log::detail::log_impl(::linjector::log::Level::Info,  fmt, ##__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LLOG_WARN(fmt, ...) \
    ::linjector::log::detail::log_impl(::linjector::log::Level::Warn,  fmt, ##__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LLOG_ERROR(fmt, ...) \
    ::linjector::log::detail::log_impl(::linjector::log::Level::Error, fmt, ##__VA_ARGS__)
