#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "../policy/maps_pins.h"

namespace cs::maps
{

bool open_pinned_maps_for_backend(const std::string &pin_base,
                                  const std::string &iface,
                                  cs_backend backend,
                                  maps_fds &out,
                                  std::string &err);

uint64_t read_percpu_sum_u64(int map_fd, uint32_t key);

std::vector<uint16_t> dump_port_set(int map_fd);

void print_ports_line(const std::string &title, const std::vector<uint16_t> &ports);

uint16_t parse_port(const std::string &s);

} // namespace cs::maps