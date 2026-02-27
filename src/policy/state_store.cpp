#include "state_store.h"

#include <sys/file.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace cs
{

static int set_err(state_error &err, const std::string &msg)
{
    err.msg = msg;
    return -1;
}

static int set_err_errno(state_error &err, const std::string &prefix)
{
    err.msg = prefix + ": " + std::string(strerror(errno));
    return -1;
}

void state_lock::close()
{
    if (fd >= 0)
    {
        ::close(fd);
        fd = -1;
    }
}

state_store::state_store(state_store_opts o, std::string ifn)
    : opt(std::move(o)), iface(std::move(ifn))
{
}

std::string state_store::base_dir() const
{
    return opt.state_root + "/" + iface;
}

std::string state_store::policies_dir() const
{
    return base_dir() + "/policies";
}

std::string state_store::lock_path() const
{
    return base_dir() + "/lock";
}

std::string state_store::active_path() const
{
    return base_dir() + "/active";
}

std::string state_store::history_path() const
{
    return base_dir() + "/history";
}

int state_store::ensure_dirs(state_error &err) const
{
    std::error_code ec;
    std::filesystem::create_directories(policies_dir(), ec);
    if (ec) return set_err(err, "create_directories failed: " + policies_dir() + ": " + ec.message());
    return 0;
}

int state_store::lock_exclusive(state_lock &lk, state_error &err) const
{
    int fd = ::open(lock_path().c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) return set_err_errno(err, "open lock file failed");

    if (flock(fd, LOCK_EX) != 0)
    {
        ::close(fd);
        return set_err_errno(err, "flock(LOCK_EX) failed");
    }

    lk.close();
    lk.fd = fd;
    return 0;
}

static int write_all(int fd, const uint8_t *p, size_t n)
{
    while (n)
    {
        ssize_t rc = ::write(fd, p, n);
        if (rc < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)rc;
        n -= (size_t)rc;
    }
    return 0;
}

static int fsync_dir_fd(int dfd)
{
    for (;;)
    {
        if (::fsync(dfd) == 0) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
}

static int fsync_dir_path(const std::string &dir)
{
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int rc = fsync_dir_fd(dfd);
    ::close(dfd);
    return rc;
}

static std::string parent_dir(const std::string &path)
{
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

static std::string make_tmp_path(const std::string &target)
{
    static std::random_device rd;
    static std::mt19937_64 rng(rd());
    uint64_t x = rng();
    std::ostringstream oss;
    oss << target << ".tmp." << (uint64_t)getpid() << "." << x;
    return oss.str();
}

static int write_file_atomic(const std::string &target,
                             const uint8_t *data,
                             size_t size,
                             mode_t mode,
                             state_error &err)
{
    std::string dir = parent_dir(target);
    std::string tmp = make_tmp_path(target);

    int fd = ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
    if (fd < 0) return set_err_errno(err, "open tmp failed");

    if (size && write_all(fd, data, size) != 0)
    {
        int e = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        errno = e;
        return set_err_errno(err, "write failed");
    }

    if (::fsync(fd) != 0)
    {
        int e = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        errno = e;
        return set_err_errno(err, "fsync failed");
    }

    if (::close(fd) != 0)
    {
        int e = errno;
        ::unlink(tmp.c_str());
        errno = e;
        return set_err_errno(err, "close failed");
    }

    if (::rename(tmp.c_str(), target.c_str()) != 0)
    {
        int e = errno;
        ::unlink(tmp.c_str());
        errno = e;
        return set_err_errno(err, "rename failed");
    }

    if (fsync_dir_path(dir) != 0)
    {
        return set_err_errno(err, "fsync(dir) failed");
    }

    return 0;
}

int state_store::store_policy_blob(const std::string &sha256,
                                  const std::vector<uint8_t> &canon,
                                  state_error &err) const
{
    std::string path = policies_dir() + "/" + sha256 + ".cbor";

    struct stat st;
    if (::stat(path.c_str(), &st) == 0)
    {
        return 0;
    }
    if (errno != ENOENT)
    {
        return set_err_errno(err, "stat failed");
    }

    return write_file_atomic(path, canon.data(), canon.size(), 0644, err);
}

int state_store::load_policy_blob(const std::string &sha256,
                                 std::vector<uint8_t> &out,
                                 state_error &err) const
{
    std::string path = policies_dir() + "/" + sha256 + ".cbor";
    std::ifstream f(path, std::ios::binary);
    if (!f) return set_err(err, "cannot open: " + path);

    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) return set_err(err, "cannot stat: " + path);
    if ((uint64_t)sz > (1ull << 20)) return set_err(err, "policy blob too large (>1MiB): " + path);

    f.seekg(0, std::ios::beg);
    out.assign((size_t)sz, 0);
    if (sz && !f.read((char *)out.data(), sz)) return set_err(err, "read failed: " + path);
    return 0;
}

static std::string trim(const std::string &s)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

int state_store::read_active(active_info &out, state_error &err) const
{
    std::ifstream f(active_path());
    if (!f)
    {
        if (errno == ENOENT) return -ENOENT;
        return set_err(err, "cannot open active");
    }

    active_info a;
    std::string line;
    while (std::getline(f, line))
    {
        line = trim(line);
        if (line.empty()) continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string k = trim(line.substr(0, pos));
        std::string v = trim(line.substr(pos + 1));

        if (k == "sha256") a.sha256 = v;
        else if (k == "kind") a.kind = v;
        else if (k == "v") a.v = (uint64_t)strtoull(v.c_str(), nullptr, 10);
        else if (k == "updated_at") a.updated_at_ms = (uint64_t)strtoull(v.c_str(), nullptr, 10);
        else if (k == "source") a.source = v;
    }

    if (a.sha256.empty())
    {
        return set_err(err, "active missing sha256");
    }

    std::string blob = policies_dir() + "/" + a.sha256 + ".cbor";
    struct stat st;
    if (::stat(blob.c_str(), &st) != 0)
    {
        return set_err(err, "active sha256 blob not found: " + blob);
    }

    out = std::move(a);
    return 0;
}

int state_store::write_active(const active_info &in, state_error &err) const
{
    if (in.sha256.empty())
    {
        return set_err(err, "active missing sha256");
    }

    std::string blob = policies_dir() + "/" + in.sha256 + ".cbor";
    struct stat st;
    if (::stat(blob.c_str(), &st) != 0)
    {
        return set_err(err, "active sha256 blob not found: " + blob);
    }

    std::ostringstream oss;
    oss << "sha256=" << in.sha256 << "\n";
    if (!in.kind.empty()) oss << "kind=" << in.kind << "\n";
    if (in.v) oss << "v=" << in.v << "\n";
    if (in.updated_at_ms) oss << "updated_at=" << in.updated_at_ms << "\n";
    if (!in.source.empty()) oss << "source=" << in.source << "\n";

    std::string s = oss.str();
    return write_file_atomic(active_path(), (const uint8_t *)s.data(), s.size(), 0644, err);
}

int state_store::read_history(std::vector<std::string> &out, state_error &err) const
{
    out.clear();
    std::ifstream f(history_path());
    if (!f)
    {
        if (errno == ENOENT) return 0;
        return set_err(err, "cannot open history");
    }

    std::string line;
    while (std::getline(f, line))
    {
        line = trim(line);
        if (!line.empty()) out.push_back(line);
    }
    return 0;
}

int state_store::write_history(const std::vector<std::string> &hist, state_error &err) const
{
    std::ostringstream oss;
    for (auto &h : hist) oss << h << "\n";
    std::string s = oss.str();
    return write_file_atomic(history_path(), (const uint8_t *)s.data(), s.size(), 0644, err);
}

void state_store::history_push(std::vector<std::string> &hist, const std::string &sha256) const
{
    if (!hist.empty() && hist.back() == sha256) return;
    hist.push_back(sha256);
    if (hist.size() > opt.max_history)
    {
        size_t drop = hist.size() - opt.max_history;
        hist.erase(hist.begin(), hist.begin() + (ptrdiff_t)drop);
    }
}

int state_store::history_pop(std::vector<std::string> &hist, state_error &err) const
{
    if (hist.size() < 2)
    {
        return set_err(err, "no previous version in history");
    }
    hist.pop_back();
    return 0;
}

} // namespace cs
