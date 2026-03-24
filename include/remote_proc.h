#pragma once
#include <string>
#include <vector>
#include "remote_mem.h"
#include "remote_module.h"
#include "errors.h"

struct MapRange {
    uintptr_t start{0};
    uintptr_t end{0};
    std::string pathname;   // e.g. /system/lib64/libc.so
    size_t offset{0};       // file offset from maps entry
    bool readable{false};
    bool writable{false};
    bool executable{false};
    size_t size() const { return end - start; }
};

/// Represents the target process.  Mirrors Rust RemoteProc.
class RemoteProc {
public:
    explicit RemoteProc(int pid);

    /// Parse /proc/<pid>/maps and return all regions.
    InjectionError maps(std::vector<MapRange> &out) const;

    /// Return all regions whose pathname ends with `name`.
    InjectionError maps_by_name(const std::string &name, std::vector<MapRange> &out) const;

    /// Build a RemoteModule for the first occurrence of `module_name`.
    InjectionError module(const std::string &module_name, RemoteModule &out) const;

    RemoteMem mem;   // public for Injector to access directly (mirrors Rust pub mem)

private:
    int pid_{0};

    InjectionError module_bytes(const std::string &module_name,
                                std::vector<uint8_t> &out) const;
};
