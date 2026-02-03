#include "maps_pins.h"

#include <bpf/bpf.h>

#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

namespace cs
{

static int set_err(maps_error &err, const std::string &msg)
{
    err.msg = msg;
    return -1;
}

static int set_err_errno(maps_error &err, const std::string &prefix)
{
    err.msg = prefix + ": " + std::string(strerror(errno));
    return -1;
}

void maps_fds::close()
{
    if (fd_cnt >= 0) ::close(fd_cnt);
    if (fd_blk_icmp >= 0) ::close(fd_blk_icmp);
    if (fd_blk_tcp >= 0) ::close(fd_blk_tcp);
    if (fd_blk_udp >= 0) ::close(fd_blk_udp);
    fd_cnt = fd_blk_icmp = fd_blk_tcp = fd_blk_udp = -1;
}

std::string backend_dir(cs_backend b)
{
    return b == cs_backend::TC ? "tc" : "xdp";
}

std::string maps_root(const maps_pins_opts &opt)
{
    return opt.pin_base + "/" + opt.iface + "/" + backend_dir(opt.backend);
}

std::string maps_dir(const maps_pins_opts &opt)
{
    return maps_root(opt) + "/maps";
}

static int open_map_checked(const std::string &path,
                            bpf_map_type type,
                            uint32_t key_sz,
                            uint32_t val_sz,
                            uint32_t max_entries,
                            int &out_fd,
                            maps_error &err)
{
    int fd = bpf_obj_get(path.c_str());
    if (fd < 0) return set_err_errno(err, "bpf_obj_get failed: " + path);

    bpf_map_info info {};
    uint32_t len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0)
    {
        ::close(fd);
        return set_err_errno(err, "bpf_obj_get_info_by_fd failed");
    }

    if ((bpf_map_type)info.type != type || info.key_size != key_sz || info.value_size != val_sz)
    {
        std::string msg = "unexpected map shape at " + path +
            ": type=" + std::to_string(info.type) +
            " key=" + std::to_string(info.key_size) +
            " value=" + std::to_string(info.value_size);
        ::close(fd);
        return set_err(err, msg);
    }

    if (max_entries && info.max_entries != max_entries)
    {
        std::string msg = "unexpected max_entries at " + path +
            ": " + std::to_string(info.max_entries) +
            " (expected " + std::to_string(max_entries) + ")";
        ::close(fd);
        return set_err(err, msg);
    }

    out_fd = fd;
    return 0;
}

int open_pinned_maps(const maps_pins_opts &opt, maps_fds &out, maps_error &err)
{
    out.close();

    std::string dir = maps_dir(opt);

    int rc = 0;

    rc = open_map_checked(dir + "/cs_cnt", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 0, out.fd_cnt, err);
    if (rc != 0) { out.close(); return rc; }

    rc = open_map_checked(dir + "/cs_blk_icmp", BPF_MAP_TYPE_ARRAY, 4, 1, 1, out.fd_blk_icmp, err);
    if (rc != 0) { out.close(); return rc; }

    rc = open_map_checked(dir + "/cs_blk_tcp", BPF_MAP_TYPE_HASH, 2, 1, 0, out.fd_blk_tcp, err);
    if (rc != 0) { out.close(); return rc; }

    rc = open_map_checked(dir + "/cs_blk_udp", BPF_MAP_TYPE_HASH, 2, 1, 0, out.fd_blk_udp, err);
    if (rc != 0) { out.close(); return rc; }

    return 0;
}

} // namespace cs
