// injector.cpp
// Top-level injection orchestrator.
// Mirrors Rust src/lib.rs  (struct Injector / impl Injector).

#include "linjector/injector.hpp"

#include <cinttypes>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "linjector/error.hpp"
#include "linjector/log.hpp"
#include "linjector/shellcode.hpp"
#include "linjector/utils.hpp"

namespace linjector {

Injector::Injector(const int pid) : pid_(pid), remote_proc_(pid) {
    LLOG_INFO("new injector for pid: %d", pid);
}

// ---------------------------------------------------------------------------
// File path
// ---------------------------------------------------------------------------

Injector& Injector::set_file_path(std::string file_path) {
    if (!std::filesystem::exists(file_path)) {
        throw InjectionException(InjectionError::FileError,
                                 "file not found: " + file_path);
    }
    file_path_ = std::move(file_path);
    return *this;
}

// Prepare the target file:
//   1. Verify ELF magic (for dlopen modes).
//   2. Copy to /data/local/tmp if needed.
//   3. Fix SELinux context and read permissions.
//   4. Print a hexdump for diagnostics.
std::string Injector::prepare_file() const {
    if (injection_type_ == InjectionType::RawDlopen ||
        injection_type_ == InjectionType::MemFdDlopen) {
        utils::verify_elf_file(file_path_);
    }
    const std::string tmp_path = utils::copy_file_to_tmp(file_path_);
    utils::fix_file_context(tmp_path);
    utils::fix_file_permissions(tmp_path);
    utils::print_file_hexdump(tmp_path);
    return tmp_path;
}

// ---------------------------------------------------------------------------
// Symbol resolution (cached)
// ---------------------------------------------------------------------------

// Mirrors Rust add_sym(): look up sym_name inside module_name, caching both
// the RemoteModule and the resolved address.
std::size_t Injector::add_sym(const std::string& module_name,
                               const std::string& sym_name) {
    LLOG_DEBUG("add_sym: %s!%s", module_name.c_str(), sym_name.c_str());
    if (!module_cache_.contains(module_name)) {
        module_cache_.emplace(module_name, remote_proc_.module(module_name));
    }
    const auto& mod = module_cache_.at(module_name);
    LLOG_DEBUG("add_sym: module '%s' vm_addr=0x%zx", module_name.c_str(), mod.vm_addr());

    if (!sym_cache_.contains(sym_name)) {
        sym_cache_.emplace(sym_name, mod.dlsym_from_fs(sym_name));
    }
    LLOG_DEBUG("add_sym: '%s' -> 0x%zx", sym_name.c_str(), sym_cache_.at(sym_name));
    return sym_cache_.at(sym_name);
}

Injector& Injector::set_func_sym(const std::string& module_name,
                                  const std::string& sym_name) {
    target_func_sym_addr_ = add_sym(module_name, sym_name);
    target_func_sym_name_ = sym_name;
    LLOG_DEBUG("set_func_sym: '%s' -> 0x%zx", sym_name.c_str(), target_func_sym_addr_);
    return *this;
}

Injector& Injector::set_var_sym(const std::string& module_name,
                                 const std::string& sym_name) {
    target_var_sym_addr_ = add_sym(module_name, sym_name);
    target_var_sym_name_ = sym_name;
    LLOG_DEBUG("set_var_sym: '%s' -> 0x%zx", sym_name.c_str(), target_var_sym_addr_);
    return *this;
}

// Default: hijack libc::malloc (function) and watch libc::timezone (variable).
Injector& Injector::set_default_syms() {
    set_func_sym("libc.so", "malloc");
    set_var_sym("libc.so", "timezone");
    return *this;
}

Injector& Injector::set_test_syms() {
    set_func_sym("liblasso.so",
                 "Java_com_github_erfur_lasso_MainActivity_testFunction");
    set_var_sym("liblasso.so", "test_var");
    return *this;
}

// ---------------------------------------------------------------------------
// Injection mode selection
// ---------------------------------------------------------------------------

Injector& Injector::use_raw_dlopen() {
    // Hijack dlopen itself so the second-stage shellcode can call it directly.
    set_func_sym("libdl.so", "dlopen");
    injection_type_ = InjectionType::RawDlopen;
    return *this;
}

Injector& Injector::use_memfd_dlopen() {
    set_func_sym("libdl.so", "dlopen");
    set_func_sym("libc.so", "sprintf");  // needed to build the /proc/self/fd path
    injection_type_ = InjectionType::MemFdDlopen;
    return *this;
}

Injector& Injector::use_raw_shellcode() {
    injection_type_ = InjectionType::RawShellcode;
    return *this;
}

// ---------------------------------------------------------------------------
// Static helper
// ---------------------------------------------------------------------------

uint32_t Injector::restart_app_and_get_pid(const std::string& package_name) {
    const uint32_t pid = utils::restart_app_and_get_pid(package_name);
    if (pid == 0) {
        throw InjectionException(InjectionError::PidNotFound,
                                 "pid not found for package: " + package_name);
    }
    return pid;
}

// ---------------------------------------------------------------------------
// Core injection logic
// Mirrors Rust Injector::inject()
// ---------------------------------------------------------------------------

void Injector::inject() {
    // 1. Prepare the file on the target device.
    const std::string file_path = prepare_file();

    // 2. Open a fresh handle to the target process memory.
    //    (Using a separate RemoteProc to mirror the Rust approach of creating
    //    a new RemoteProc inside inject().)
    RemoteProc proc(pid_);

    // 3. Fall back to default symbols if none were provided.
    if (target_func_sym_name_.empty() || target_var_sym_name_.empty()) {
        LLOG_WARN("target_func_sym or target_var_sym is empty, using defaults");
        set_default_syms();
    }

    // 4. Build stage-2 shellcode (the payload that runs on the mmap'd page).
    LLOG_INFO("build second stage shellcode");
    std::vector<uint8_t> second_stage;
    switch (injection_type_) {
        case InjectionType::RawDlopen:
            LLOG_INFO("injection mode: raw-dlopen  dlopen=0x%zx  oldfun=0x%zx",
                      sym_cache_.at("dlopen"), target_func_sym_addr_);
            second_stage = shellcode::raw_dlopen_shellcode(
                sym_cache_.at("dlopen"),
                file_path,
                target_func_sym_addr_);
            break;

        case InjectionType::MemFdDlopen: {
            LLOG_INFO("injection mode: memfd-dlopen  dlopen=0x%zx  sprintf=0x%zx",
                      sym_cache_.at("dlopen"), sym_cache_.at("sprintf"));
            std::ifstream fin(file_path, std::ios::binary);
            const std::vector<uint8_t> lib_bytes(
                (std::istreambuf_iterator<char>(fin)),
                std::istreambuf_iterator<char>());
            LLOG_INFO("library data size: %zu bytes", lib_bytes.size());
            second_stage = shellcode::memfd_dlopen_shellcode(
                sym_cache_.at("dlopen"),
                target_func_sym_addr_,
                lib_bytes,
                sym_cache_.at("sprintf"));
            break;
        }

        case InjectionType::RawShellcode:
            LLOG_INFO("injection mode: raw-shellcode");
            second_stage = shellcode::raw_shellcode();
            break;
    }
    LLOG_INFO("second stage size: %zu bytes", second_stage.size());

    // 5. Build stage-1 shellcode (overwrites the prologue of the hijacked function).
    LLOG_INFO("build first stage shellcode");
    const auto first_stage =
        shellcode::main_shellcode(target_var_sym_addr_, second_stage.size());
    LLOG_INFO("first stage size: %zu bytes", first_stage.size());

    // 6. Save original bytes so we can restore them later.
    LLOG_INFO("read original bytes at func=0x%zx var=0x%zx",
              target_func_sym_addr_, target_var_sym_addr_);
    const auto func_original_bytes =
        proc.mem.read(target_func_sym_addr_, first_stage.size());
    const auto var_original_bytes =
        proc.mem.read(target_var_sym_addr_, 0x8);

    // 7. Plant stage-1.
    LLOG_INFO("write first stage shellcode -> 0x%zx", target_func_sym_addr_);
    proc.mem.write(target_var_sym_addr_, std::vector<uint8_t>(0x8, 0));
    proc.mem.write(target_func_sym_addr_, first_stage);

    // 8. Wait until stage-1 runs.
    LLOG_INFO("wait for shellcode to trigger...");
    uint64_t new_map = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        const auto data = proc.mem.read(target_var_sym_addr_, 0x8);
        if (data.size() < 8) continue;

        new_map =
            static_cast<uint64_t>(data[0])        |
            (static_cast<uint64_t>(data[1]) << 8U)  |
            (static_cast<uint64_t>(data[2]) << 16U) |
            (static_cast<uint64_t>(data[3]) << 24U) |
            (static_cast<uint64_t>(data[4]) << 32U) |
            (static_cast<uint64_t>(data[5]) << 40U) |
            (static_cast<uint64_t>(data[6]) << 48U) |
            (static_cast<uint64_t>(data[7]) << 56U);

        if ((new_map & 0x1ULL) != 0 &&
            (new_map & 0xFFFFFFFFFFFFFFF0ULL) != 0) {
            break;
        }
    }

    new_map &= 0xFFFFFFFFFFFFFFF0ULL;
    LLOG_INFO("new map: 0x%" PRIx64, new_map);

    // 9. Spin the hijacked function while we write stage-2.
    LLOG_INFO("overwrite hijacked func with self-loop");
    proc.mem.write(target_func_sym_addr_, shellcode::self_jmp());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 10. Restore original bytes.
    LLOG_INFO("restore original bytes");
    proc.mem.write_code(target_func_sym_addr_, func_original_bytes, 1);
    proc.mem.write(target_var_sym_addr_, var_original_bytes);

    // 11. Write stage-2 onto the mmap'd page.
    LLOG_INFO("overwrite new map -> 0x%" PRIx64, new_map);
    proc.mem.write_code(static_cast<std::size_t>(new_map), second_stage, 1);

    LLOG_INFO("injection done.");
}

}  // namespace linjector
