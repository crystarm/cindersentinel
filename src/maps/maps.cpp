#include "maps.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "../io_utils/io_utils.h"
#include "../policy/limits.h"

namespace cs::maps
{

bool open_pinned_maps_for_backend(const std::string &pin_base,
                                  const std::string &iface,
                                  cs_backend backend,
                                  maps_fds &out,
                                  std::string &err)
{
    cs::maps_pins_opts opt;
    opt.pin_base = pin_base;
    opt.iface = iface;
    opt.backend = backend;

    cs::maps_error e;
    if (cs::open_pinned_maps(opt, out, e) != 0)
    {
        err = e.msg;
        return false;
    }

    return true;
}

uint64_t read_percpu_sum_u64(int map_fd, uint32_t key)
{
    const int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) return 0;

    std::vector<uint64_t> per_cpu(static_cast<size_t>(cpu_count), 0);
    if (bpf_map_lookup_elem(map_fd, &key, per_cpu.data()) != 0) return 0;

    uint64_t sum = 0;
    for (int i = 0; i < cpu_count; ++i) sum += per_cpu[static_cast<size_t>(i)];
    return sum;
}

std::vector<uint16_t> dump_port_set(int map_fd)
{
    std::vector<uint16_t> ports;
    uint8_t v = 0;

    for (uint32_t key = 1; key < cs::CS_PORT_MAP_MAX; ++key)
    {
        if (bpf_map_lookup_elem(map_fd, &key, &v) == 0 && v != 0)
            ports.push_back(static_cast<uint16_t>(key));
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

void print_ports_line(const std::string &title, const std::vector<uint16_t> &ports)
{
    std::cout << title;
    if (ports.empty())
    {
        std::cout << "none\n";
        return;
    }

    for (size_t i = 0; i < ports.size(); ++i)
    {
        if (i) std::cout << ",";
        std::cout << ports[i];
    }
    std::cout << "\n";
}

uint16_t parse_port(const std::string &s)
{
    char *end = nullptr;
    const long v = std::strtol(s.c_str(), &end, 10);

    if (s.empty() || (end && *end))
        cs::io_utils::die("bad port: " + s);
    if (v < 1 || v > 65535)
        cs::io_utils::die("port out of range: " + s);

    return static_cast<uint16_t>(v);
}

} // namespace cs::maps