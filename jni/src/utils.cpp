#include "linjector/utils.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include <cstdio>

#include "linjector/error.hpp"
#include "linjector/log.hpp"

namespace linjector::utils {

namespace {

constexpr std::size_t HEXDUMP_BUFFER_SIZE = 0x200;
constexpr const char* TMP_DIR_PATH = "/data/local/tmp";

std::string shell_join(const std::string& program, const std::vector<std::string>& args) {
    std::ostringstream oss;
    oss << program;
    for (const auto& a : args) {
        oss << " '" << a << "'";
    }
    return oss.str();
}

}  // namespace

void print_file_hexdump(const std::string& file_path) {
    std::ifstream fin(file_path, std::ios::binary);
    if (!fin) {
        LLOG_ERROR("error opening file for hexdump: %s", file_path.c_str());
        throw InjectionException(InjectionError::FileError, "open file failed for hexdump: " + file_path);
    }

    std::vector<uint8_t> buffer(HEXDUMP_BUFFER_SIZE, 0);
    fin.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

    // Debug: print first 64 bytes as hex
    const std::size_t n = static_cast<std::size_t>(fin.gcount());
    if (n > 0) {
        char hex[256] = {};
        std::size_t pos = 0;
        for (std::size_t i = 0; i < n && i < 16 && pos + 3 < sizeof(hex); ++i) {
            pos += static_cast<std::size_t>(
                snprintf(hex + pos, sizeof(hex) - pos, "%02x ", buffer[i]));
        }
        LLOG_DEBUG("hexdump of '%s' (first 16 bytes): %s", file_path.c_str(), hex);
    }
}

void verify_elf_file(const std::string& file_path) {
    LLOG_DEBUG("verifying ELF magic: %s", file_path.c_str());
    std::ifstream fin(file_path, std::ios::binary);
    if (!fin) {
        LLOG_ERROR("error opening file: %s", file_path.c_str());
        throw InjectionException(InjectionError::FileError, "open file failed: " + file_path);
    }
    uint8_t magic[4]{0};
    fin.read(reinterpret_cast<char*>(magic), 4);
    if (!fin || !(magic[0] == 0x7f && magic[1] == 0x45 && magic[2] == 0x4c && magic[3] == 0x46)) {
        LLOG_ERROR("file is not an ELF: %s", file_path.c_str());
        throw InjectionException(InjectionError::FileError, "not an ELF file: " + file_path);
    }
    LLOG_DEBUG("ELF magic OK: %s", file_path.c_str());
}

std::string copy_file_to_tmp(const std::string& file_path) {
    std::filesystem::path abs = std::filesystem::canonical(file_path);
    const std::string abs_str = abs.string();
    LLOG_INFO("file path: %s", abs_str.c_str());

    if (abs_str.rfind(TMP_DIR_PATH, 0) == 0) {
        LLOG_INFO("file is already in %s", TMP_DIR_PATH);
        return abs_str;
    }

    const auto target = std::filesystem::path(TMP_DIR_PATH) / abs.filename();
    const std::string target_str = target.string();
    LLOG_INFO("copying '%s' -> '%s'", abs_str.c_str(), target_str.c_str());
    std::filesystem::copy_file(abs, target, std::filesystem::copy_options::overwrite_existing);
    LLOG_INFO("file copied successfully");
    return target_str;
}

void fix_file_context(const std::string& file_path) {
    LLOG_INFO("fixing file SELinux context: %s", file_path.c_str());
    const auto out = execute_command("chcon", {"u:object_r:apk_data_file:s0", file_path});
    if (out.exit_code != 0) {
        LLOG_ERROR("chcon failed: %s", out.stderr_text.c_str());
        throw InjectionException(InjectionError::CommandError, "chcon failed: " + out.stderr_text);
    }
    LLOG_INFO("file context fixed");
}

void fix_file_permissions(const std::string& file_path) {
    LLOG_INFO("fixing file permissions: %s", file_path.c_str());
    const auto out = execute_command("chmod", {"+r", file_path});
    if (out.exit_code != 0) {
        LLOG_ERROR("chmod failed: %s", out.stderr_text.c_str());
        throw InjectionException(InjectionError::CommandError, "chmod failed: " + out.stderr_text);
    }
    LLOG_INFO("file permissions fixed");
}

CommandOutput execute_command(const std::string& program, const std::vector<std::string>& args) {
    const std::string cmd = shell_join(program, args) + " 2>&1";
    LLOG_DEBUG("execute_command: %s", cmd.c_str());
    FILE* pipe = ::popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
        LLOG_ERROR("popen failed: %s", cmd.c_str());
        throw InjectionException(InjectionError::CommandError, "popen failed for command: " + cmd);
    }

    std::string output;
    char chunk[512];
    while (true) {
        const auto n = std::fread(chunk, 1, sizeof(chunk), pipe);
        if (n == 0) {
            break;
        }
        output.append(chunk, n);
    }

    const int status = ::pclose(pipe);
    CommandOutput out;
    out.exit_code = status;
    out.stdout_text = output;
    if (status != 0) {
        LLOG_WARN("command exited with status %d: %s", status, cmd.c_str());
    } else {
        LLOG_DEBUG("command succeeded: %s", cmd.c_str());
    }
    return out;
}

uint32_t get_pid_by_package(const std::string& pkg_name) {
    for (const auto& dir_entry : std::filesystem::directory_iterator("/proc")) {
        if (!dir_entry.is_directory()) {
            continue;
        }
        const auto name = dir_entry.path().filename().string();
        if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }

        const auto cmdline_path = dir_entry.path() / "cmdline";
        std::ifstream fin(cmdline_path, std::ios::binary);
        if (!fin) {
            continue;
        }
        std::string cmdline((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        if (!cmdline.empty() && cmdline.back() == '\0') {
            cmdline.pop_back();
        }
        if (cmdline == pkg_name) {
            return static_cast<uint32_t>(std::stoul(name));
        }
    }
    return 0;
}

uint32_t get_pid_by_package_with_polling(const std::string& pkg_name) {
    constexpr int count = 100;
    for (int i = 0; i < count; ++i) {
        const uint32_t pid = get_pid_by_package(pkg_name);
        if (pid > 0) {
            return pid;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
    return 0;
}

uint32_t restart_app_and_get_pid(const std::string& pkg_name) {
    LLOG_INFO("restarting app: %s", pkg_name.c_str());
    (void)execute_command("am", {"force-stop", pkg_name});
    (void)execute_command("monkey", {"-p", pkg_name, "-c", "android.intent.category.LAUNCHER", "1"});

    uint32_t pid = get_pid_by_package_with_polling(pkg_name);
    if (pid > 0) {
        return pid;
    }

    const auto out = execute_command("cmd", {"package", "resolve-activity", "--brief", pkg_name});
    std::istringstream iss(out.stdout_text);
    std::string line;
    std::string last;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            last = line;
        }
    }
    if (!last.empty()) {
        (void)execute_command("am", {"start", last});
    }
    pid = get_pid_by_package_with_polling(pkg_name);
    return pid;
}

}  // namespace linjector::utils

