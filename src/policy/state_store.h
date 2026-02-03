#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cs
{

struct state_error
{
    std::string msg;
};

struct active_info
{
    std::string sha256;
    std::string kind;
    uint64_t v = 0;
    uint64_t updated_at_ms = 0;
    std::string source;
};

struct state_store_opts
{
    std::string state_root = "/var/lib/cindersentinel";
    size_t max_history = 64;
};

struct state_lock
{
    int fd = -1;

    state_lock() = default;
    state_lock(const state_lock &) = delete;
    state_lock &operator=(const state_lock &) = delete;

    state_lock(state_lock &&o) noexcept
    {
        fd = o.fd;
        o.fd = -1;
    }

    state_lock &operator=(state_lock &&o) noexcept
    {
        if (this != &o)
        {
            close();
            fd = o.fd;
            o.fd = -1;
        }
        return *this;
    }

    ~state_lock()
    {
        close();
    }

    void close();
};

struct state_store
{
    state_store_opts opt;
    std::string iface;

    explicit state_store(state_store_opts o, std::string ifn);

    std::string base_dir() const;
    std::string policies_dir() const;
    std::string lock_path() const;
    std::string active_path() const;
    std::string history_path() const;

    int ensure_dirs(state_error &err) const;

    int lock_exclusive(state_lock &lk, state_error &err) const;

    int store_policy_blob(const std::string &sha256,
                          const std::vector<uint8_t> &canon,
                          state_error &err) const;

    int load_policy_blob(const std::string &sha256,
                         std::vector<uint8_t> &out,
                         state_error &err) const;

    int read_active(active_info &out, state_error &err) const;
    int write_active(const active_info &in, state_error &err) const;

    int read_history(std::vector<std::string> &out, state_error &err) const;
    int write_history(const std::vector<std::string> &hist, state_error &err) const;

    void history_push(std::vector<std::string> &hist, const std::string &sha256) const;
    int history_pop(std::vector<std::string> &hist, state_error &err) const;
};

} // namespace cs
