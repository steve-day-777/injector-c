#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include "errors.h"
#include "remote_proc.h"

enum class InjectionType {
    RawDlopen,    ///< Call dlopen() with the path of the file on the target device
    MemFdDlopen,  ///< Write the SO into a memfd, call dlopen("/proc/self/fd/<fd>")
    RawShellcode, ///< Inject and execute arbitrary shellcode
};

class Injector {
public:
    /// Create an injector for `pid`.
    static InjectionError create(int pid, Injector &out);

    /// Set the local path to the file/shellcode to inject.
    InjectionError set_file_path(const std::string &file_path);

    // ---------- symbol configuration ----------

    /// Resolve `sym_name` inside `module_name` and register it as the function
    /// whose prologue will be overwritten (the "hook point").
    InjectionError set_func_sym(const std::string &module_name,
                                const std::string &sym_name);

    /// Resolve `sym_name` inside `module_name` and register it as the watched
    /// variable used as a signal/rendezvous with the injected shellcode.
    InjectionError set_var_sym(const std::string &module_name,
                               const std::string &sym_name);

    /// Use libc::malloc as the function hook and libc::timezone as the variable.
    InjectionError set_default_syms();

    // ---------- injection mode ----------

    InjectionError use_raw_dlopen();
    InjectionError use_memfd_dlopen();
    InjectionError use_raw_shellcode();

    // ---------- static helpers ----------

    /// Force-stop and relaunch a package, then return its pid.
    static InjectionError restart_app_and_get_pid(const std::string &package_name,
                                                  uint32_t &out_pid);

    // ---------- inject ----------
    InjectionError inject();

private:
    Injector() = default;

    InjectionError prepare_file(std::string &out_path);
    InjectionError add_sym(const std::string &module_name,
                           const std::string &sym_name,
                           uintptr_t &out_addr);

    int pid_{0};
    RemoteProc *proc_{nullptr};    // heap-allocated so RemoteProc can be moved-in
    std::string file_path_;
    InjectionType injection_type_{InjectionType::RawDlopen};

    std::string target_func_sym_name_;
    uintptr_t   target_func_sym_addr_{0};
    std::string target_var_sym_name_;
    uintptr_t   target_var_sym_addr_{0};

    std::unordered_map<std::string, RemoteModule> module_cache_;
    std::unordered_map<std::string, uintptr_t>    sym_cache_;
};
