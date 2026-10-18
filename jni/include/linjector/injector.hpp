#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "linjector/remote_module.hpp"
#include "linjector/remote_proc.hpp"

namespace linjector {

enum class InjectionType {
    RawDlopen,
    MemFdDlopen,
    RawShellcode
};

class Injector {
public:
    explicit Injector(int pid);

    Injector& set_file_path(std::string file_path);
    Injector& set_func_sym(const std::string& module_name, const std::string& sym_name);
    Injector& set_var_sym(const std::string& module_name, const std::string& sym_name);
    Injector& set_default_syms();
    Injector& set_test_syms();
    Injector& use_raw_dlopen();
    Injector& use_memfd_dlopen();
    Injector& use_raw_shellcode();
    Injector& set_hide(bool hide);

    static uint32_t restart_app_and_get_pid(const std::string& package_name);
    void inject();

private:
    std::string prepare_file() const;
    std::size_t add_sym(const std::string& module_name, const std::string& sym_name);
    uint64_t run_stage(RemoteProc& proc, const std::vector<uint8_t>& stage2);
    void post_inject_hide(RemoteProc& proc, const std::string& lib_path);
    void hide_soinfo(RemoteProc& proc, const std::string& lib_path);

    int pid_{0};
    RemoteProc remote_proc_;
    std::string file_path_;
    InjectionType injection_type_{InjectionType::RawDlopen};
    bool hide_{false};

    std::string target_func_sym_name_;
    std::size_t target_func_sym_addr_{0};
    std::string target_var_sym_name_;
    std::size_t target_var_sym_addr_{0};

    std::unordered_map<std::string, RemoteModule> module_cache_;
    std::unordered_map<std::string, std::size_t> sym_cache_;
};

}  // namespace linjector

