#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace linjector::shellcode {

std::vector<uint8_t> main_shellcode(std::size_t var_addr, std::size_t alloc_len);
std::vector<uint8_t> raw_dlopen_shellcode(std::size_t dlopen_addr, const std::string& dlopen_path, std::size_t jmp_addr);
std::vector<uint8_t> memfd_dlopen_shellcode(std::size_t dlopen_addr, std::size_t jmp_addr, const std::vector<uint8_t>& library_data_bytes, std::size_t sprintf_addr);
std::vector<uint8_t> raw_shellcode();
std::vector<uint8_t> self_jmp();

}  // namespace linjector::shellcode

