#include "io_utils.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>

namespace cs::io_utils
{

[[noreturn]] void die(const std::string &msg)
{
    std::cerr << "cindersentinel: " << msg << "\n";
    std::exit(2);
}

std::vector<uint8_t> read_file_all(const std::string &path, size_t max_size_bytes)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) die("cannot open file: " + path);

    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) die("cannot stat file: " + path);

    if (static_cast<uint64_t>(sz) > static_cast<uint64_t>(max_size_bytes))
        die("policy file too large (>1MiB): " + path);

    f.seekg(0, std::ios::beg);

    std::vector<uint8_t> bytes(static_cast<size_t>(sz));
    if (sz > 0 && !f.read(reinterpret_cast<char *>(bytes.data()), sz))
        die("read failed: " + path);

    return bytes;
}

void write_file_all(const std::string &path, const std::vector<uint8_t> &bytes)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) die("cannot write: " + path);

    if (!bytes.empty())
        f.write(reinterpret_cast<const char *>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));

    if (!f) die("write failed: " + path);
}

int write_all_fd(int fd, const uint8_t *data, size_t size)
{
    while (size > 0)
    {
        ssize_t rc = ::write(fd, data, size);
        if (rc < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        data += static_cast<size_t>(rc);
        size -= static_cast<size_t>(rc);
    }
    return 0;
}

} // namespace cs::io_utils