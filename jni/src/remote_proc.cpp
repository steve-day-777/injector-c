#include "linjector/remote_proc.hpp"

#include <fstream>
#include <sstream>

#include "linjector/error.hpp"
#include "linjector/log.hpp"

namespace linjector {

namespace {

bool ends_with(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) {
        return false;
    }
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

RemoteProc::RemoteProc(const int pid) : mem(pid), pid_(pid) {
    LLOG_DEBUG("RemoteProc: attached to pid %d", pid);
}

std::vector<MapRange> RemoteProc::maps() const {
    const std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream fin(maps_path);
    if (!fin) {
        throw InjectionException(InjectionError::RemoteProcessError, "open maps failed: " + maps_path);
    }

    std::vector<MapRange> result;
    std::string line;
    while (std::getline(fin, line)) {
        std::istringstream iss(line);
        std::string addr_range;
        std::string perms;
        std::string offset_hex;
        std::string dev;
        std::string inode;

        if (!(iss >> addr_range >> perms >> offset_hex >> dev >> inode)) {
            continue;
        }

        std::string pathname;
        std::getline(iss, pathname);
        if (!pathname.empty() && pathname[0] == ' ') {
            pathname.erase(pathname.begin());
        }

        const auto sep = addr_range.find('-');
        if (sep == std::string::npos) {
            continue;
        }

        MapRange m;
        m.start = std::stoull(addr_range.substr(0, sep), nullptr, 16);
        m.end = std::stoull(addr_range.substr(sep + 1), nullptr, 16);
        m.offset = std::stoull(offset_hex, nullptr, 16);
        m.perms = perms;
        m.pathname = pathname;
        result.push_back(std::move(m));
    }
    return result;
}

std::vector<MapRange> RemoteProc::maps_by_name(const std::string& name) const {
    std::vector<MapRange> out;
    for (const auto& m : maps()) {
        if (!m.pathname.empty() && ends_with(m.pathname, name)) {
            out.push_back(m);
        }
    }
    if (out.empty()) {
        LLOG_ERROR("module not found in /proc/%d/maps: %s", pid_, name.c_str());
        throw InjectionException(InjectionError::ModuleNotFound, "module not found: " + name);
    }
    LLOG_DEBUG("maps_by_name: found %zu region(s) for '%s'", out.size(), name.c_str());
    return out;
}

std::vector<uint8_t> RemoteProc::module_bytes(const std::string& module_name) const {
    const auto ranges = maps_by_name(module_name);
    std::vector<uint8_t> bytes;

    for (const auto& r : ranges) {
        if (bytes.size() < r.offset) {
            bytes.resize(r.offset, 0);
        }
        auto part = mem.read(r.start, r.size());
        bytes.insert(bytes.end(), part.begin(), part.end());
    }
    return bytes;
}

RemoteModule RemoteProc::module(const std::string& module_name) const {
    const auto ranges = maps_by_name(module_name);
    LLOG_INFO("module '%s': path=%s vm_addr=0x%zx",
              module_name.c_str(), ranges[0].pathname.c_str(), ranges[0].start);
    return RemoteModule(ranges[0].pathname, ranges[0].start, module_bytes(module_name));
}

}  // namespace linjector

