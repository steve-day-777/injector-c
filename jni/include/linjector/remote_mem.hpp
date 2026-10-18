#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace linjector {

class RemoteMem {
public:
    explicit RemoteMem(int pid);
    ~RemoteMem();

    RemoteMem(const RemoteMem&) = delete;
    RemoteMem& operator=(const RemoteMem&) = delete;
    RemoteMem(RemoteMem&& other) noexcept;
    RemoteMem& operator=(RemoteMem&& other) noexcept;

    [[nodiscard]] std::vector<uint8_t> read(std::size_t addr, std::size_t len) const;
    void read_vec(std::size_t addr, std::vector<uint8_t>& buf) const;
    void write(std::size_t addr, const std::vector<uint8_t>& buf) const;
    void write_code(std::size_t addr, const std::vector<uint8_t>& buf, std::size_t skip_instructions) const;

private:
    int fd_{-1};
};

}  // namespace linjector

