#include "linjector/remote_module.hpp"

#include <elf.h>

#include <cstring>
#include <fstream>

#include "linjector/error.hpp"
#include "linjector/log.hpp"

namespace linjector {

namespace {

// Extract the filename component from an absolute path.
std::string basename_of(const std::string& path) {
    const auto pos = path.rfind('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// Build an ordered list of candidate filesystem paths for a shared library.
//
// On Android 10+ (APEX), bionic libraries (libdl.so, libc.so, libm.so, …)
// are reported in /proc/<pid>/maps as:
//   /apex/com.android.runtime/lib64/bionic/<lib>.so
// but that path may not be directly openable from the injector process.
// We therefore try a prioritised fallback list:
//
//   1. The exact path from /proc/maps               (always first)
//   2. /system<apex-path>                            (APEX mounted under /system on some ROMs)
//   3. /system/lib64/<basename>                      (traditional location)
//   4. /system/lib/<basename>                        (32-bit fallback, rarely relevant here)
//   5. /apex/com.android.runtime/lib64/bionic/<basename>  (bionic APEX canonical)
//   6. /vendor/lib64/<basename>                      (vendor partition)
//   7. /vendor/lib/<basename>
std::vector<std::string> candidate_paths(const std::string& primary) {
    const std::string base = basename_of(primary);
    std::vector<std::string> cands;
    cands.push_back(primary);

    // APEX path seen in maps -> also try it mounted under /system
    if (primary.rfind("/apex/", 0) == 0) {
        cands.push_back("/system" + primary);
    }

    cands.push_back("/system/lib64/" + base);
    cands.push_back("/system/lib/"   + base);
    cands.push_back("/apex/com.android.runtime/lib64/bionic/" + base);
    cands.push_back("/vendor/lib64/" + base);
    cands.push_back("/vendor/lib/"   + base);

    // Deduplicate while preserving order
    std::vector<std::string> unique;
    for (const auto& c : cands) {
        bool found = false;
        for (const auto& u : unique) { if (u == c) { found = true; break; } }
        if (!found) unique.push_back(c);
    }
    return unique;
}

// Attempt to read an ELF file, trying candidate paths in order.
// Throws FileError only after all candidates are exhausted.
std::vector<uint8_t> read_elf_file(const std::string& primary_path) {
    const auto cands = candidate_paths(primary_path);
    std::string last_err;

    for (const auto& path : cands) {
        LLOG_DEBUG("trying ELF path: %s", path.c_str());
        std::ifstream fin(path, std::ios::binary);
        if (!fin) {
            last_err = path;
            continue;
        }
        fin.seekg(0, std::ios::end);
        const auto size = static_cast<std::size_t>(fin.tellg());
        fin.seekg(0, std::ios::beg);
        std::vector<uint8_t> data(size);
        fin.read(reinterpret_cast<char*>(data.data()),
                 static_cast<std::streamsize>(size));
        if (fin) {
            LLOG_INFO("loaded ELF from: %s", path.c_str());
            return data;
        }
        last_err = path;
    }

    throw InjectionException(InjectionError::FileError,
                             "open file failed: " + primary_path +
                             " (also tried " + std::to_string(cands.size() - 1) +
                             " fallback paths)");
}

const Elf64_Shdr* section_by_type(const uint8_t* base, const Elf64_Ehdr* ehdr, uint32_t type, int nth = 0) {
    const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);
    int seen = 0;
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_type == type) {
            if (seen == nth) {
                return &shdr[i];
            }
            ++seen;
        }
    }
    return nullptr;
}

std::size_t lookup_in_table(const uint8_t* base, const Elf64_Shdr* symtab, const Elf64_Shdr* strtab, const std::string& symbol_name, std::size_t vm_addr) {
    const auto* syms = reinterpret_cast<const Elf64_Sym*>(base + symtab->sh_offset);
    const std::size_t sym_count = symtab->sh_size / sizeof(Elf64_Sym);
    const auto* strs = reinterpret_cast<const char*>(base + strtab->sh_offset);

    for (std::size_t i = 0; i < sym_count; ++i) {
        const char* name = strs + syms[i].st_name;
        if (symbol_name == name) {
            return vm_addr + static_cast<std::size_t>(syms[i].st_value);
        }
    }
    return 0;
}

}  // namespace

RemoteModule::RemoteModule(std::string name, const std::size_t vm_addr, std::vector<uint8_t> bytes)
    : name_(std::move(name)), vm_addr_(vm_addr), bytes_(std::move(bytes)) {}

std::size_t RemoteModule::dlsym_from_fs(const std::string& symbol_name) const {
    LLOG_DEBUG("dlsym: looking up '%s' in module '%s' (vm_addr=0x%zx)",
               symbol_name.c_str(), name_.c_str(), vm_addr_);
    const auto bytes = read_elf_file(name_);
    if (bytes.size() < sizeof(Elf64_Ehdr)) {
        throw InjectionException(InjectionError::RemoteModuleError, "invalid ELF: too small");
    }

    const auto* base = bytes.data();
    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        throw InjectionException(InjectionError::RemoteModuleError, "invalid ELF64 file: " + name_);
    }

    const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(base + ehdr->e_shoff);

    const Elf64_Shdr* symtab = section_by_type(base, ehdr, SHT_SYMTAB);
    if (symtab != nullptr) {
        const Elf64_Shdr* strtab = &shdr[symtab->sh_link];
        const std::size_t addr = lookup_in_table(base, symtab, strtab, symbol_name, vm_addr_);
        if (addr != 0) {
            LLOG_DEBUG("dlsym: '%s' found in .symtab at 0x%zx", symbol_name.c_str(), addr);
            return addr;
        }
    }

    LLOG_WARN("symbol not found in .symtab, trying .dynsym: %s", symbol_name.c_str());

    const Elf64_Shdr* dynsym = section_by_type(base, ehdr, SHT_DYNSYM);
    if (dynsym != nullptr) {
        const Elf64_Shdr* dynstr = &shdr[dynsym->sh_link];
        const std::size_t addr = lookup_in_table(base, dynsym, dynstr, symbol_name, vm_addr_);
        if (addr != 0) {
            LLOG_DEBUG("dlsym: '%s' found in .dynsym at 0x%zx", symbol_name.c_str(), addr);
            return addr;
        }
    }

    LLOG_ERROR("symbol not found: %s", symbol_name.c_str());
    throw InjectionException(InjectionError::SymbolNotFound, "symbol not found: " + symbol_name);
}

}  // namespace linjector

