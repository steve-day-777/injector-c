#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "errors.h"

namespace shellcode {

/// Stage-1: mmap a RWX page, write a self-jmp there, signal the address back
/// through the watched variable, then branch to the new page.
/// Equivalent to Rust main_shellcode().
InjectionError main_shellcode(uintptr_t var_addr,
                              size_t    alloc_len,
                              std::vector<uint8_t> &out);

/// Stage-2 (raw dlopen): call dlopen(path, RTLD_NOW), restore registers,
/// jump back to the original function.
/// Equivalent to Rust raw_dlopen_shellcode().
InjectionError raw_dlopen_shellcode(uintptr_t dlopen_addr,
                                    const std::string &dlopen_path,
                                    uintptr_t jmp_addr,
                                    std::vector<uint8_t> &out);

/// Stage-2 (memfd dlopen): memfd_create + write library bytes + dlopen via
/// /proc/self/fd/<fd>, restore registers, jump to original function.
/// Equivalent to Rust memfd_dlopen_shellcode().
InjectionError memfd_dlopen_shellcode(uintptr_t dlopen_addr,
                                      uintptr_t jmp_addr,
                                      const std::vector<uint8_t> &library_data,
                                      uintptr_t sprintf_addr,
                                      std::vector<uint8_t> &out);

/// 4-byte aarch64 self-jump instruction (b #0).
/// Used to put the hijacked function into a spin while we write stage-2.
InjectionError self_jmp(std::vector<uint8_t> &out);

} // namespace shellcode
