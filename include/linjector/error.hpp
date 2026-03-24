#pragma once

#include <stdexcept>
#include <string>

namespace linjector {

enum class InjectionError {
    RemoteProcessError,
    RemoteMemoryError,
    RemoteModuleError,
    ModuleNotFound,
    SymbolNotFound,
    FileError,
    CommandError,
    ShellcodeError,
    PidNotFound,
    ArgError
};

class InjectionException : public std::runtime_error {
public:
    InjectionException(InjectionError code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    [[nodiscard]] InjectionError code() const noexcept { return code_; }

private:
    InjectionError code_;
};

}  // namespace linjector

