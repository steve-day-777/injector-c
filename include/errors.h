#pragma once

enum class InjectionError {
    None = 0,
    RemoteProcessError,
    RemoteMemoryError,
    RemoteModuleError,
    ModuleNotFound,
    SymbolNotFound,
    FileError,
    CommandError,
    ShellcodeError,
    PidNotFound,
};

inline const char *injection_error_str(InjectionError e) {
    switch (e) {
    case InjectionError::None:               return "None";
    case InjectionError::RemoteProcessError: return "RemoteProcessError";
    case InjectionError::RemoteMemoryError:  return "RemoteMemoryError";
    case InjectionError::RemoteModuleError:  return "RemoteModuleError";
    case InjectionError::ModuleNotFound:     return "ModuleNotFound";
    case InjectionError::SymbolNotFound:     return "SymbolNotFound";
    case InjectionError::FileError:          return "FileError";
    case InjectionError::CommandError:       return "CommandError";
    case InjectionError::ShellcodeError:     return "ShellcodeError";
    case InjectionError::PidNotFound:        return "PidNotFound";
    default:                                 return "Unknown";
    }
}
