#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace linjector::utils {

void print_file_hexdump(const std::string& file_path);
void verify_elf_file(const std::string& file_path);
std::string copy_file_to_tmp(const std::string& file_path);
void fix_file_context(const std::string& file_path);
void fix_file_permissions(const std::string& file_path);

struct CommandOutput {
    int exit_code{0};
    std::string stdout_text;
    std::string stderr_text;
};

CommandOutput execute_command(const std::string& program, const std::vector<std::string>& args);
uint32_t get_pid_by_package(const std::string& pkg_name);
uint32_t get_pid_by_package_with_polling(const std::string& pkg_name);
uint32_t restart_app_and_get_pid(const std::string& pkg_name);

}  // namespace linjector::utils

