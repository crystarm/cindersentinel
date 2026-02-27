#include "aegis_c_api.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace
{
struct AdaResult
{
    bool ok = false;
    bool timeout = false;
    int exit_code = -1;
    std::string output;
};

static std::string trim_copy(const std::string &s)
{
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\n' || s[b] == '\r' || s[b] == '\t'))
        ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\n' || s[e - 1] == '\r' || s[e - 1] == '\t'))
        --e;
    return s.substr(b, e - b);
}

static std::string hex_dump(const uint8_t *data, size_t len)
{
    static const char *hexd = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        uint8_t b = data[i];
        out.push_back(hexd[b >> 4]);
        out.push_back(hexd[b & 0x0f]);
    }
    return out;
}

static bool write_all_fd(int fd, const uint8_t *p, size_t n)
{
    while (n)
    {
        ssize_t rc = ::write(fd, p, n);
        if (rc < 0)
        {
            if (errno == EINTR) continue;
            return false;
        }
        p += (size_t)rc;
        n -= (size_t)rc;
    }
    return true;
}

static AdaResult run_ada_validator(const uint8_t *data, size_t len, int timeout_ms)
{
    AdaResult res;

    char tmp[] = "/tmp/cindersentinel-aegis.XXXXXX";
    int fd = ::mkstemp(tmp);
    if (fd < 0)
    {
        res.output = std::string("mkstemp failed: ") + std::strerror(errno);
        return res;
    }

    bool wrote = true;
    if (len > 0)
    {
        wrote = write_all_fd(fd, data, len);
    }

    if (!wrote)
    {
        res.output = std::string("write temp file failed: ") + std::strerror(errno);
        ::close(fd);
        ::unlink(tmp);
        return res;
    }

    if (::close(fd) != 0)
    {
        res.output = std::string("close temp file failed: ") + std::strerror(errno);
        ::unlink(tmp);
        return res;
    }

    int pipefd[2];
    if (::pipe(pipefd) != 0)
    {
        res.output = std::string("pipe failed: ") + std::strerror(errno);
        ::unlink(tmp);
        return res;
    }

    pid_t pid = ::fork();
    if (pid < 0)
    {
        res.output = std::string("fork failed: ") + std::strerror(errno);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::unlink(tmp);
        return res;
    }

    if (pid == 0)
    {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);

        const char *env_bin = std::getenv("CINDERSENTINEL_AEGIS");
        const char *bin = (env_bin && *env_bin) ? env_bin : "cindersentinel-aegis";
        ::execlp(bin, bin, tmp, (char *)nullptr);
        _exit(127);
    }

    ::close(pipefd[1]);

    int flags = ::fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) ::fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    std::string output;
    output.reserve(1024);

    int status = 0;
    bool exited = false;

    auto start = std::chrono::steady_clock::now();
    while (true)
    {
        char buf[4096];
        while (true)
        {
            ssize_t rc = ::read(pipefd[0], buf, sizeof(buf));
            if (rc > 0)
            {
                output.append(buf, (size_t)rc);
                continue;
            }
            if (rc == 0)
            {
                break;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            break;
        }

        if (!exited)
        {
            pid_t w = ::waitpid(pid, &status, WNOHANG);
            if (w == pid) exited = true;
        }

        if (exited)
        {
            // Drain remaining output
            while (true)
            {
                char buf2[4096];
                ssize_t rc = ::read(pipefd[0], buf2, sizeof(buf2));
                if (rc > 0)
                {
                    output.append(buf2, (size_t)rc);
                    continue;
                }
                break;
            }
            break;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (elapsed_ms > timeout_ms)
        {
            res.timeout = true;
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            break;
        }

        ::usleep(1000);
    }

    ::close(pipefd[0]);
    ::unlink(tmp);

    res.output = output;
    if (!res.timeout)
    {
        if (WIFEXITED(status))
        {
            res.exit_code = WEXITSTATUS(status);
        }
        else if (WIFSIGNALED(status))
        {
            res.exit_code = 128 + WTERMSIG(status);
        }
        res.ok = (res.exit_code == 0);
    }

    return res;
}

static void crash_mismatch(const std::string &why,
                           const std::string &cpp_err,
                           const AdaResult &ada,
                           const uint8_t *data,
                           size_t len)
{
    std::string ada_out = trim_copy(ada.output);
    std::string cpp_out = trim_copy(cpp_err);

    std::fprintf(stderr, "aegis-fuzz: mismatch: %s\n", why.c_str());
    std::fprintf(stderr, "c++ ok: %s\n", cpp_out.empty() ? "true" : "false");
    std::fprintf(stderr, "c++ err: %s\n", cpp_out.empty() ? "<empty>" : cpp_out.c_str());
    std::fprintf(stderr, "ada ok: %s\n", ada.ok ? "true" : "false");
    std::fprintf(stderr, "ada exit: %d\n", ada.exit_code);
    std::fprintf(stderr, "ada timeout: %s\n", ada.timeout ? "true" : "false");
    std::fprintf(stderr, "ada out: %s\n", ada_out.empty() ? "<empty>" : ada_out.c_str());
    std::fprintf(stderr, "input_len: %zu\n", len);
    std::string hex = hex_dump(data, len);
    std::fprintf(stderr, "input_hex: %s\n", hex.c_str());
    std::fflush(stderr);
    std::abort();
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char err_buf[4096] = {};
    int rc = aegis_validate(data, size, err_buf, sizeof(err_buf));
    bool cpp_ok = (rc == 0);
    std::string cpp_err = cpp_ok ? std::string() : (err_buf[0] ? std::string(err_buf) : std::string("validation failed"));

    AdaResult ada = run_ada_validator(data, size, 1000);

    if (ada.timeout)
    {
        crash_mismatch("ada timeout", cpp_err, ada, data, size);
    }

    if (cpp_ok != ada.ok)
    {
        crash_mismatch("success mismatch", cpp_err, ada, data, size);
    }

    if (!cpp_ok)
    {
        std::string ada_err = trim_copy(ada.output);
        std::string cpp_err_trim = trim_copy(cpp_err);
        if (ada_err != cpp_err_trim)
        {
            crash_mismatch("error text mismatch", cpp_err, ada, data, size);
        }
    }

    return 0;
}