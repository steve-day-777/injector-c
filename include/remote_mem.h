#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include "errors.h"

/// Wraps /proc/<pid>/mem for non-ptrace memory read/write using pread/pwrite.
class RemoteMem {
public:
    explicit RemoteMem(int pid);
    ~RemoteMem();

    // Non-copyable, movable
    RemoteMem(const RemoteMem &) = delete;
    RemoteMem &operator=(const RemoteMem &) = delete;
    RemoteMem(RemoteMem &&) noexcept;
    RemoteMem &operator=(RemoteMem &&) noexcept;

    /// Read `len` bytes from remote address `addr`.
    InjectionError read(uintptr_t addr, size_t len, std::vector<uint8_t> &out) const;

    /// Write bytes to remote address `addr`.
    InjectionError write(uintptr_t addr, const std::vector<uint8_t> &buf) const;

    /// Write code, writing everything from `skip*4` first, then the skipped head last.
    /// This minimises the window during which a thread executing the patched function
    /// sees a partially-written stub (mirrors Rust write_code).
    InjectionError write_code(uintptr_t addr, const std::vector<uint8_t> &buf, size_t skip) const;

    bool is_valid() const { return fd_ >= 0; }

private:
    int fd_{-1};
};
