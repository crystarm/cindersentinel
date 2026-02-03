#pragma once

#include <cstdint>
#include <string>

namespace cs
{

enum class cs_backend
{
    TC,
    XDP,
};

struct maps_error
{
    std::string msg;
};

struct maps_fds
{
    int fd_cnt = -1;
    int fd_blk_icmp = -1;
    int fd_blk_tcp = -1;
    int fd_blk_udp = -1;

    maps_fds() = default;
    maps_fds(const maps_fds &) = delete;
    maps_fds &operator=(const maps_fds &) = delete;

    maps_fds(maps_fds &&o) noexcept
    {
        *this = std::move(o);
    }

    maps_fds &operator=(maps_fds &&o) noexcept
    {
        if (this != &o)
        {
            close();
            fd_cnt = o.fd_cnt;
            fd_blk_icmp = o.fd_blk_icmp;
            fd_blk_tcp = o.fd_blk_tcp;
            fd_blk_udp = o.fd_blk_udp;
            o.fd_cnt = o.fd_blk_icmp = o.fd_blk_tcp = o.fd_blk_udp = -1;
        }
        return *this;
    }

    ~maps_fds()
    {
        close();
    }

    void close();
};

struct maps_pins_opts
{
    std::string pin_base = "/sys/fs/bpf/cindersentinel";
    std::string iface;
    cs_backend backend = cs_backend::TC;
};

std::string backend_dir(cs_backend b);

std::string maps_root(const maps_pins_opts &opt);
std::string maps_dir(const maps_pins_opts &opt);

int open_pinned_maps(const maps_pins_opts &opt, maps_fds &out, maps_error &err);

} // namespace cs
