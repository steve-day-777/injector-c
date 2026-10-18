#include "linjector/log.hpp"

namespace linjector::log {

// Default: Info (same as Rust's simple_logger default without --debug flag).
Level g_min_level = Level::Info;

}  // namespace linjector::log
