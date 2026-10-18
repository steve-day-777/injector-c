#include "linjector/remote_mem.hpp"

#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "linjector/error.hpp"
#include "linjector/log.hpp"

namespace linjector {

RemoteMem::RemoteMem(const int pid) {
    const std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    fd_ = ::open(mem_path.c_str(), O_RDWR);
    if (fd_ < 0) {
        throw InjectionException(InjectionError::RemoteMemoryError, "open /proc/pid/mem failed: " + std::string(std::strerror(errno)));
    }
}

RemoteMem::~RemoteMem() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

RemoteMem::RemoteMem(RemoteMem&& other) noexcept {
    fd_ = other.fd_;
    other.fd_ = -1;
}

RemoteMem& RemoteMem::operator=(RemoteMem&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

std::vector<uint8_t> RemoteMem::read(const std::size_t addr, const std::size_t len) const {
    std::vector<uint8_t> buf(len);
    read_vec(addr, buf);
    return buf;
}

void RemoteMem::read_vec(const std::size_t addr, std::vector<uint8_t>& buf) const {
    LLOG_DEBUG("reading from remote memory: addr=0x%zx len=%zu", addr, buf.size());
    const ssize_t n = ::pread(fd_, buf.data(), buf.size(), static_cast<off_t>(addr));
    if (n < 0 || static_cast<std::size_t>(n) != buf.size()) {
        LLOG_ERROR("pread failed at 0x%zx len=%zu: %s", addr, buf.size(), std::strerror(errno));
        throw InjectionException(InjectionError::RemoteMemoryError, "pread failed: " + std::string(std::strerror(errno)));
    }
}

void RemoteMem::write(const std::size_t addr, const std::vector<uint8_t>& buf) const {
    LLOG_DEBUG("writing into remote memory: addr=0x%zx len=%zu", addr, buf.size());
    const ssize_t n = ::pwrite(fd_, buf.data(), buf.size(), static_cast<off_t>(addr));
    if (n < 0 || static_cast<std::size_t>(n) != buf.size()) {
        LLOG_ERROR("pwrite failed at 0x%zx len=%zu: %s", addr, buf.size(), std::strerror(errno));
        throw InjectionException(InjectionError::RemoteMemoryError, "pwrite failed: " + std::string(std::strerror(errno)));
    }
}

void RemoteMem::write_code(const std::size_t addr, const std::vector<uint8_t>& buf, const std::size_t skip_instructions) const {
    const std::size_t skip_offset = skip_instructions * 4;
    if (skip_offset > buf.size()) {
        throw InjectionException(InjectionError::RemoteMemoryError, "write_code skip out of range");
    }

    const ssize_t n1 = ::pwrite(fd_, buf.data() + skip_offset, buf.size() - skip_offset, static_cast<off_t>(addr + skip_offset));
    if (n1 < 0 || static_cast<std::size_t>(n1) != (buf.size() - skip_offset)) {
        throw InjectionException(InjectionError::RemoteMemoryError, "pwrite code tail failed: " + std::string(std::strerror(errno)));
    }

    const ssize_t n2 = ::pwrite(fd_, buf.data(), skip_offset, static_cast<off_t>(addr));
    if (n2 < 0 || static_cast<std::size_t>(n2) != skip_offset) {
        throw InjectionException(InjectionError::RemoteMemoryError, "pwrite code head failed: " + std::string(std::strerror(errno)));
    }
}

}  // namespace linjector

