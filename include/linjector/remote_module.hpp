#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace linjector {

class RemoteModule {
public:
    RemoteModule(std::string name, std::size_t vm_addr, std::vector<uint8_t> bytes);

    [[nodiscard]] std::size_t dlsym_from_fs(const std::string& symbol_name) const;
    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] std::size_t vm_addr() const noexcept { return vm_addr_; }

private:
    std::string name_;
    std::size_t vm_addr_{0};
    std::vector<uint8_t> bytes_;
};

}  // namespace linjector

