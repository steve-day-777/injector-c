// injector.cpp
// Top-level injection orchestrator.
// Mirrors Rust src/lib.rs  (struct Injector / impl Injector).

#include "linjector/injector.hpp"

#include <cinttypes>
#include <chrono>
#include <cstring>
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

Injector& Injector::set_hide(bool hide) {
    hide_ = hide;
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
// run_stage — generic stage-1 + stage-2 executor.
// Plants stage-1 over the hijacked function, waits for the mmap'd page,
// writes stage-2 there, restores the original bytes.
// Returns the mmap'd page address (for later reuse).
// ---------------------------------------------------------------------------

uint64_t Injector::run_stage(RemoteProc& proc, const std::vector<uint8_t>& stage2) {
    LLOG_INFO("build first stage shellcode");
    const auto first_stage =
        shellcode::main_shellcode(target_var_sym_addr_, stage2.size());
    LLOG_INFO("first stage size: %zu bytes", first_stage.size());

    LLOG_INFO("read original bytes at func=0x%zx var=0x%zx",
              target_func_sym_addr_, target_var_sym_addr_);
    const auto func_original_bytes =
        proc.mem.read(target_func_sym_addr_, first_stage.size());
    const auto var_original_bytes =
        proc.mem.read(target_var_sym_addr_, 0x8);

    LLOG_INFO("write first stage shellcode -> 0x%zx", target_func_sym_addr_);
    proc.mem.write(target_var_sym_addr_, std::vector<uint8_t>(0x8, 0));
    proc.mem.write(target_func_sym_addr_, first_stage);

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

    LLOG_INFO("overwrite hijacked func with self-loop");
    proc.mem.write(target_func_sym_addr_, shellcode::self_jmp());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LLOG_INFO("restore original bytes");
    proc.mem.write_code(target_func_sym_addr_, func_original_bytes, 1);
    proc.mem.write(target_var_sym_addr_, var_original_bytes);

    LLOG_INFO("overwrite new map -> 0x%" PRIx64, new_map);
    proc.mem.write_code(static_cast<std::size_t>(new_map), stage2, 1);

    return new_map;
}

// ---------------------------------------------------------------------------
// post_inject_hide — remap library segments to anonymous + label jit-cache.
// Uses a second hijack of the same function to run hide shellcode inside
// the target process.
// ---------------------------------------------------------------------------

namespace {

uint32_t perms_to_prot(const std::string& perms) {
    uint32_t prot = 0;
    if (perms.size() >= 3) {
        if (perms[0] == 'r') prot |= 1;  // PROT_READ
        if (perms[1] == 'w') prot |= 2;  // PROT_WRITE
        if (perms[2] == 'x') prot |= 4;  // PROT_EXEC
    }
    return prot;
}

}  // namespace

void Injector::post_inject_hide(RemoteProc& proc, const std::string& lib_path) {
    LLOG_INFO("=== post-inject hide: remap segments to jit-cache ===");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto all_maps = proc.maps();
    std::vector<shellcode::SegmentInfo> segments;
    const std::string basename = std::filesystem::path(lib_path).filename().string();

    for (const auto& m : all_maps) {
        if (m.pathname.empty()) continue;
        const auto slash = m.pathname.rfind('/');
        const std::string map_base = (slash != std::string::npos)
            ? m.pathname.substr(slash + 1) : m.pathname;
        if (map_base == basename) {
            shellcode::SegmentInfo seg;
            seg.addr = static_cast<uint64_t>(m.start);
            seg.size = static_cast<uint64_t>(m.size());
            seg.prot = perms_to_prot(m.perms);
            segments.push_back(seg);
            LLOG_INFO("  segment: 0x%" PRIx64 " size=0x%" PRIx64 " prot=%u perms=%s",
                      seg.addr, seg.size, seg.prot, m.perms.c_str());
        }
    }

    if (segments.empty()) {
        LLOG_WARN("no library segments found in maps for '%s'", basename.c_str());
        return;
    }

    LLOG_INFO("found %zu segments to hide", segments.size());

    const auto hide_stage2 = shellcode::hide_shellcode(segments, target_func_sym_addr_);
    LLOG_INFO("hide shellcode size: %zu bytes", hide_stage2.size());

    run_stage(proc, hide_stage2);

    LLOG_INFO("maps hide complete");
}

// ---------------------------------------------------------------------------
// hide_soinfo — erase the library name from the linker's soinfo structures
// and from heap-allocated realpath strings.
//
// After dlopen, the linker creates a soinfo node containing the library path.
// The soinfo itself lives in anonymous pages allocated by the linker's
// internal allocator (labelled [anon:linker_alloc*] in /proc/pid/maps),
// NOT in the linker ELF's own .data/.bss.  The realpath_ string is often
// strdup'd into the general heap ([anon:libc_malloc] / [anon:scudo:*]).
//
// We scan all of these writable regions for the library name and zero
// every occurrence via /proc/pid/mem.
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t MAX_SCAN_REGION_SIZE = 32 * 1024 * 1024;  // 32 MB

std::size_t scan_and_erase(RemoteMem& mem, const MapRange& region,
                           const std::string& needle) {
    if (region.size() > MAX_SCAN_REGION_SIZE) return 0;

    std::vector<uint8_t> data;
    try {
        data = mem.read(region.start, region.size());
    } catch (...) {
        return 0;
    }

    const auto* haystack = reinterpret_cast<const char*>(data.data());
    const std::size_t hlen = data.size();
    const std::size_t nlen = needle.size();
    std::size_t count = 0;

    for (std::size_t off = 0; off + nlen <= hlen; ++off) {
        if (std::memcmp(haystack + off, needle.c_str(), nlen) == 0) {
            const std::size_t addr = region.start + off;
            LLOG_INFO("  found '%s' at 0x%zx [%s] — zeroing",
                      needle.c_str(), addr, region.pathname.c_str());
            std::vector<uint8_t> zeros(nlen, 0);
            try {
                mem.write(addr, zeros);
                ++count;
            } catch (...) {
                LLOG_WARN("  write failed at 0x%zx", addr);
            }
        }
    }
    return count;
}

}  // namespace

void Injector::hide_soinfo(RemoteProc& proc, const std::string& lib_path) {
    LLOG_INFO("=== hide soinfo: erase library name from linker ===");

    const std::string basename = std::filesystem::path(lib_path).filename().string();
    const auto all_maps = proc.maps();

    std::vector<MapRange> targets;
    for (const auto& m : all_maps) {
        if (m.perms.size() >= 2 && m.perms[1] == 'w' && m.size() <= MAX_SCAN_REGION_SIZE) {
            targets.push_back(m);
        }
    }

    LLOG_INFO("scanning %zu candidate regions for '%s'",
              targets.size(), basename.c_str());

    std::size_t erased = 0;

    for (const auto& region : targets) {
        erased += scan_and_erase(proc.mem, region, basename);
        if (lib_path != basename) {
            erased += scan_and_erase(proc.mem, region, lib_path);
        }
    }

    LLOG_INFO("soinfo hide: erased %zu name occurrence(s)", erased);
}

// ---------------------------------------------------------------------------
// Core injection logic
// Mirrors Rust Injector::inject()
// ---------------------------------------------------------------------------

void Injector::inject() {
    // 1. Prepare the file on the target device.
    const std::string file_path = prepare_file();

    // 2. Open a fresh handle to the target process memory.
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

    // 5. Run the injection (stage-1 + stage-2).
    run_stage(proc, second_stage);
    LLOG_INFO("injection done.");

    // 6. Post-injection hiding (if requested).
    if (hide_) {
        post_inject_hide(proc, file_path);
        hide_soinfo(proc, file_path);
        LLOG_INFO("post-injection hiding complete.");
    }
}

}  // namespace linjector
