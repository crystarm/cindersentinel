#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cs::io_utils
{

[[noreturn]] void die(const std::string &msg);

std::vector<uint8_t> read_file_all(const std::string &path,
                                   size_t max_size_bytes = (1ull << 20));

void write_file_all(const std::string &path, const std::vector<uint8_t> &bytes);

int write_all_fd(int fd, const uint8_t *data, size_t size);

} // namespace cs::io_utils