#include "aegis_c_api.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void die(const std::string &msg)
{
    std::cerr << "aegis: " << msg << "\n";
    std::exit(2);
}

static std::vector<uint8_t> read_file_all(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) die("cannot open file: " + path);

    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) die("cannot stat file: " + path);

    if ((uint64_t)sz > (1ull << 20)) die("policy file too large (>1MiB): " + path);

    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b((size_t)sz);
    if (sz && !f.read(reinterpret_cast<char *>(b.data()), sz))
        die("read failed: " + path);

    return b;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: cindersentinel-aegis <policy.cbor>\n";
        return 2;
    }

    std::string path = argv[1];
    auto bytes = read_file_all(path);

    char err_buf[4096] = {};
    int rc = aegis_validate(bytes.data(), bytes.size(), err_buf, sizeof(err_buf));
    if (rc != 0)
    {
        std::string msg = err_buf[0] ? err_buf : "validation failed";
        std::cerr << "aegis: " << msg << "\n";
        return 2;
    }

    std::cout << "OK\n";
    return 0;
}