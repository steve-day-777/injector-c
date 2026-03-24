#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "errors.h"

/// Represents one loaded shared library inside the target process.
/// Symbol resolution is done by parsing the on-disk ELF (same approach as Rust goblin).
class RemoteModule {
public:
    RemoteModule(const std::string &name, uintptr_t vm_addr, std::vector<uint8_t> bytes);

    /// Look up `symbol_name` by scanning .symtab then .dynsym of the on-disk ELF.
    /// Returns the in-process virtual address (file offset + vm_addr).
    InjectionError dlsym_from_fs(const std::string &symbol_name, uintptr_t &out_addr) const;

    const std::string &name() const { return name_; }
    uintptr_t vm_addr() const { return vm_addr_; }

private:
    std::string name_;
    uintptr_t vm_addr_{0};
    std::vector<uint8_t> bytes_;  // in-memory copy (kept for potential future use)
};
