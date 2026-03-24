#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "linjector/remote_mem.hpp"
#include "linjector/remote_module.hpp"

namespace linjector {

struct MapRange {
    std::size_t start{0};
    std::size_t end{0};
    std::size_t offset{0};
    std::string perms;
    std::string pathname;

    [[nodiscard]] std::size_t size() const noexcept { return end - start; }
};

class RemoteProc {
public:
    explicit RemoteProc(int pid);

    [[nodiscard]] int pid() const noexcept { return pid_; }
    [[nodiscard]] std::vector<MapRange> maps() const;
    [[nodiscard]] std::vector<MapRange> maps_by_name(const std::string& name) const;
    [[nodiscard]] std::vector<uint8_t> module_bytes(const std::string& module_name) const;
    [[nodiscard]] RemoteModule module(const std::string& module_name) const;

    RemoteMem mem;

private:
    int pid_{0};
};

}  // namespace linjector

