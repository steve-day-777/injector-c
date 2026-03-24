#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "errors.h"

namespace utils {

/// Print first 0x200 bytes of a file as a hex dump (debug).
InjectionError print_file_hexdump(const std::string &file_path);

/// Verify the first 4 bytes are the ELF magic \x7fELF.
InjectionError verify_elf_file(const std::string &file_path);

/// Copy `file_path` into /data/local/tmp/ if it is not already there.
/// Returns the destination path.
InjectionError copy_file_to_tmp(const std::string &file_path, std::string &out_path);

/// Run: chcon u:object_r:apk_data_file:s0 <file>
InjectionError fix_file_context(const std::string &file_path);

/// Run: chmod +r <file>
InjectionError fix_file_permissions(const std::string &file_path);

/// Generic command runner, returns false if process exits non-zero.
InjectionError execute_command(const std::string &program,
                               const std::vector<std::string> &args);

/// Scan /proc/*/cmdline to find the pid of `pkg_name`.  Returns 0 if not found.
uint32_t get_pid_by_package(const std::string &pkg_name);

/// Poll get_pid_by_package() up to 100 times with 500 µs sleep between tries.
uint32_t get_pid_by_package_with_polling(const std::string &pkg_name);

/// Force-stop and relaunch an Android app, then return its pid.
uint32_t restart_app_and_get_pid(const std::string &pkg_name);

/// Read entire file into a byte vector.
InjectionError read_file(const std::string &path, std::vector<uint8_t> &out);

} // namespace utils
