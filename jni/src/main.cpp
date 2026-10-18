#include <iostream>
#include <string>
#include <vector>

#include "linjector/error.hpp"
#include "linjector/injector.hpp"
#include "linjector/log.hpp"
#include "linjector/utils.hpp"

using linjector::InjectionType;
using linjector::Injector;

namespace {

struct Args {
    int pid = 0;
    std::string app_package_name;
    std::string file;
    InjectionType injection_type = InjectionType::RawDlopen;
    std::string func_sym;
    std::string var_sym;
    bool debug = false;
    bool logcat = false;
    bool hide = false;
};

void print_help() {
    std::cout
        << "Usage: linjector-cli --file <FILE> [options]\n"
        << "  -p, --pid <PID>\n"
        << "  -a, --app-package-name <NAME>\n"
        << "  -f, --file <FILE>\n"
        << "  -i, --injection-type <raw-dlopen|memfd-dlopen|raw-shellcode>\n"
        << "      --func-sym <lib.so!symbol>\n"
        << "      --var-sym <lib.so!symbol>\n"
        << "      --hide              remap segments to jit-cache + erase soinfo\n"
        << "  -d, --debug\n"
        << "      --logcat\n";
}

std::vector<std::string> split_sym(const std::string& s) {
    const auto p = s.find('!');
    if (p == std::string::npos || p == 0 || p + 1 >= s.size()) {
        throw linjector::InjectionException(linjector::InjectionError::ArgError, "invalid symbol format: " + s);
    }
    return {s.substr(0, p), s.substr(p + 1)};
}

Args parse_args(const int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string cur = argv[i];
        auto require_next = [&](const std::string& opt) -> std::string {
            if (i + 1 >= argc) {
                throw linjector::InjectionException(linjector::InjectionError::ArgError, "missing value for " + opt);
            }
            return argv[++i];
        };

        if (cur == "-p" || cur == "--pid") {
            a.pid = std::stoi(require_next(cur));
        } else if (cur == "-a" || cur == "--app-package-name") {
            a.app_package_name = require_next(cur);
        } else if (cur == "-f" || cur == "--file") {
            a.file = require_next(cur);
        } else if (cur == "-i" || cur == "--injection-type") {
            const std::string v = require_next(cur);
            if (v == "raw-dlopen") {
                a.injection_type = InjectionType::RawDlopen;
            } else if (v == "memfd-dlopen") {
                a.injection_type = InjectionType::MemFdDlopen;
            } else if (v == "raw-shellcode") {
                a.injection_type = InjectionType::RawShellcode;
            } else {
                throw linjector::InjectionException(linjector::InjectionError::ArgError, "invalid injection type: " + v);
            }
        } else if (cur == "--func-sym") {
            a.func_sym = require_next(cur);
        } else if (cur == "--var-sym") {
            a.var_sym = require_next(cur);
        } else if (cur == "--hide") {
            a.hide = true;
        } else if (cur == "-d" || cur == "--debug") {
            a.debug = true;
        } else if (cur == "--logcat") {
            a.logcat = true;
        } else if (cur == "-h" || cur == "--help") {
            print_help();
            std::exit(0);
        } else {
            throw linjector::InjectionException(linjector::InjectionError::ArgError, "unknown arg: " + cur);
        }
    }
    if (a.file.empty()) {
        throw linjector::InjectionException(linjector::InjectionError::ArgError, "--file is required");
    }
    return a;
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        const Args args = parse_args(argc, argv);

        // Initialise log level (mirrors Rust --debug / --logcat flags)
        if (args.debug) {
            linjector::log::set_level(linjector::log::Level::Debug);
        } else {
            linjector::log::set_level(linjector::log::Level::Info);
        }
        // --logcat: on Android the log backend already writes to logcat;
        // no extra init needed here.

        int target_pid = args.pid;
        if (target_pid <= 0) {
            if (args.app_package_name.empty()) {
                throw linjector::InjectionException(linjector::InjectionError::ArgError,
                                                    "No pid or app_package_name is specified");
            }
            target_pid = static_cast<int>(
                linjector::utils::get_pid_by_package(args.app_package_name));
            if (target_pid <= 0) {
                throw linjector::InjectionException(linjector::InjectionError::PidNotFound,
                    "process not running: " + args.app_package_name);
            }
        }

        LLOG_INFO("target process pid: %d", target_pid);

        Injector injector(target_pid);
        injector.set_file_path(args.file);

        switch (args.injection_type) {
            case InjectionType::RawDlopen:
                injector.use_raw_dlopen();
                break;
            case InjectionType::MemFdDlopen:
                injector.use_memfd_dlopen();
                break;
            case InjectionType::RawShellcode:
                injector.use_raw_shellcode();
                break;
        }

        if (!args.func_sym.empty()) {
            const auto sym_pair = split_sym(args.func_sym);
            injector.set_func_sym(sym_pair[0], sym_pair[1]);
        }
        if (!args.var_sym.empty()) {
            const auto sym_pair = split_sym(args.var_sym);
            injector.set_var_sym(sym_pair[0], sym_pair[1]);
        }

        if (args.func_sym.empty() || args.var_sym.empty()) {
            LLOG_WARN("function or variable symbol not specified, using defaults");
            injector.set_default_syms();
        }

        if (args.hide) {
            injector.set_hide(true);
        }

        injector.inject();
        LLOG_INFO("injection successful");
        std::cout << "[INFO ] injection successful\n";
        return 0;
    } catch (const linjector::InjectionException& e) {
        LLOG_ERROR("%s", e.what());
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        LLOG_ERROR("unexpected: %s", e.what());
        std::cerr << "[ERROR] unexpected: " << e.what() << "\n";
        return 1;
    }
}
