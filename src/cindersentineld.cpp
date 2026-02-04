#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/if_link.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static volatile sig_atomic_t g_should_exit = 0;

static void handle_signal(int)
{
    g_should_exit = 1;
}

static int set_memlock_unlimited()
{
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    return setrlimit(RLIMIT_MEMLOCK, &limit);
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
    {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

enum class backend_kind
{
    tc,
    xdp
};

enum class xdp_mode
{
    generic,
    native
};

static const char *backend_str(backend_kind b)
{
    switch (b)
    {
        case backend_kind::tc: return "tc";
        case backend_kind::xdp: return "xdp";
    }
    return "tc";
}

static const char *xdp_mode_str(xdp_mode m)
{
    switch (m)
    {
        case xdp_mode::generic: return "generic";
        case xdp_mode::native: return "native";
    }
    return "generic";
}

struct options
{
    std::string interface_name;

    backend_kind backend;
    bool backend_set = false;

    std::string object_path;
    bool object_set = false;

    std::string section_name;
    bool section_set = false;

    xdp_mode xdp_mode_kind = xdp_mode::generic;

    std::string pin_root = "/sys/fs/bpf/cindersentinel";
    bool pin_enabled = true;

    int interval_ms = 1000;
    bool detach_only = false;
    bool print_once = false;
};

static void print_usage(const char *argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " --backend tc|xdp --iface <ifname> [--obj <path>] [--sec <section>]\n"
        << "        [--xdp-mode generic|native] [--pin-root <path>] [--no-pin]\n"
        << "        [--interval-ms <n>] [--once]\n"
        << "  " << argv0 << " --backend tc|xdp --iface <ifname> [--xdp-mode generic|native] --detach\n";
}

static bool parse_int(const char *s, int &out)
{
    char *end = nullptr;
    long v = strtol(s, &end, 10);
    if (!s[0] || (end && *end))
    {
        return false;
    }
    if (v < 0 || v > 3600 * 1000)
    {
        return false;
    }
    out = (int)v;
    return true;
}

static bool parse_backend(const std::string &s, backend_kind &out)
{
    if (s == "tc")
    {
        out = backend_kind::tc;
        return true;
    }
    if (s == "xdp")
    {
        out = backend_kind::xdp;
        return true;
    }
    return false;
}

static bool parse_xdp_mode(const std::string &s, xdp_mode &out)
{
    if (s == "generic")
    {
        out = xdp_mode::generic;
        return true;
    }
    if (s == "native")
    {
        out = xdp_mode::native;
        return true;
    }
    return false;
}

static void apply_backend_defaults(options &opts)
{
    if (!opts.backend_set)
    {
        return;
    }

    if (!opts.object_set)
    {
        if (opts.backend == backend_kind::tc)
        {
            opts.object_path = "build/cindersentinel_tc.bpf.o";
        }
        else
        {
            opts.object_path = "build/cindersentinel_xdp.bpf.o";
        }
    }

    if (!opts.section_set)
    {
        if (opts.backend == backend_kind::tc)
        {
            opts.section_name = "classifier";
        }
        else
        {
            opts.section_name = "xdp";
        }
    }
}

static bool parse_args(int argc, char **argv, options &opts)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];

        auto need_value = [&](const char *flag) -> const char *
        {
            if (i + 1 >= argc)
            {
                std::cerr << flag << " requires a value\n";
                return nullptr;
            }
            return argv[++i];
        };

        if (a == "--backend")
        {
            const char *v = need_value("--backend");
            if (!v)
            {
                return false;
            }
            if (!parse_backend(v, opts.backend))
            {
                std::cerr << "Bad --backend value (expected: tc|xdp)\n";
                return false;
            }
            opts.backend_set = true;
        }
        else if (a == "--iface")
        {
            const char *v = need_value("--iface");
            if (!v)
            {
                return false;
            }
            opts.interface_name = v;
        }
        else if (a == "--obj")
        {
            const char *v = need_value("--obj");
            if (!v)
            {
                return false;
            }
            opts.object_path = v;
            opts.object_set = true;
        }
        else if (a == "--sec")
        {
            const char *v = need_value("--sec");
            if (!v)
            {
                return false;
            }
            opts.section_name = v;
            opts.section_set = true;
        }
        else if (a == "--xdp-mode")
        {
            const char *v = need_value("--xdp-mode");
            if (!v)
            {
                return false;
            }
            if (!parse_xdp_mode(v, opts.xdp_mode_kind))
            {
                std::cerr << "Bad --xdp-mode value (expected: generic|native)\n";
                return false;
            }
        }
        else if (a == "--pin-root")
        {
            const char *v = need_value("--pin-root");
            if (!v)
            {
                return false;
            }
            opts.pin_root = v;
        }
        else if (a == "--no-pin")
        {
            opts.pin_enabled = false;
        }
        else if (a == "--interval-ms")
        {
            const char *v = need_value("--interval-ms");
            if (!v)
            {
                return false;
            }
            if (!parse_int(v, opts.interval_ms))
            {
                std::cerr << "Bad --interval-ms value\n";
                return false;
            }
        }
        else if (a == "--detach")
        {
            opts.detach_only = true;
        }
        else if (a == "--once")
        {
            opts.print_once = true;
        }
        else if (a == "-h" || a == "--help")
        {
            print_usage(argv[0]);
            exit(0);
        }
        else
        {
            std::cerr << "Unknown argument: " << a << "\n";
            return false;
        }
    }

    if (!opts.backend_set)
    {
        std::cerr << "--backend is required\n";
        return false;
    }

    if (opts.interface_name.empty())
    {
        std::cerr << "--iface is required\n";
        return false;
    }

    apply_backend_defaults(opts);
    return true;
}

static uint64_t read_percpu_counter_sum(int map_fd, uint32_t key)
{
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0)
    {
        return 0;
    }

    std::vector<uint64_t> per_cpu_values((size_t)cpu_count, 0);

    if (bpf_map_lookup_elem(map_fd, &key, per_cpu_values.data()) != 0)
    {
        return 0;
    }

    uint64_t sum = 0;
    for (int i = 0; i < cpu_count; ++i)
    {
        sum += per_cpu_values[(size_t)i];
    }
    return sum;
}

static bool is_tc_absent_rc(int rc)
{
    return rc == -ENOENT || rc == -EINVAL;
}

static void init_tc_hook(struct bpf_tc_hook &hook, int ifindex, enum bpf_tc_attach_point attach_point)
{
    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = attach_point;
}

static void init_tc_opts(struct bpf_tc_opts &opts, int handle, int priority)
{
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.handle = handle;
    opts.priority = priority;
}

static void print_tc_err(const char *what, int rc)
{
    if (rc < 0)
    {
        std::cerr << what << " failed: " << strerror(-rc) << " (" << rc << ")\n";
        return;
    }
    std::cerr << what << " failed: " << rc << "\n";
}

static bool path_is_dir(const std::string &p)
{
    struct stat st {};
    if (stat(p.c_str(), &st) != 0)
    {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

static bool mkdir_p(const std::string &path, mode_t mode)
{
    if (path.empty())
    {
        return false;
    }

    std::string cur;
    cur.reserve(path.size());

    for (size_t i = 0; i < path.size(); ++i)
    {
        char c = path[i];
        cur.push_back(c);

        bool last = (i + 1 == path.size());
        if (c != '/' && !last)
        {
            continue;
        }

        std::string dir = cur;
        while (!dir.empty() && dir.back() == '/')
        {
            dir.pop_back();
        }

        if (dir.empty())
        {
            continue;
        }

        if (mkdir(dir.c_str(), mode) != 0)
        {
            if (errno != EEXIST)
            {
                std::cerr << "mkdir failed: " << dir << ": " << strerror(errno) << "\n";
                return false;
            }
            if (!path_is_dir(dir))
            {
                std::cerr << "not a directory: " << dir << "\n";
                return false;
            }
        }
    }

    return true;
}

static bool unlink_if_exists(const std::string &path)
{
    if (unlink(path.c_str()) != 0)
    {
        if (errno == ENOENT)
        {
            return true;
        }
        std::cerr << "unlink failed: " << path << ": " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

static bool pin_one_map(bpf_object *object, const std::string &maps_dir, const std::string &name)
{
    bpf_map *m = bpf_object__find_map_by_name(object, name.c_str());
    if (!m)
    {
        std::cerr << "Map not found: " << name << "\n";
        return false;
    }

    std::string path = maps_dir + "/" + name;

    if (!unlink_if_exists(path))
    {
        return false;
    }

    int rc = bpf_map__pin(m, path.c_str());
    if (rc != 0)
    {
        std::cerr << "bpf_map__pin failed for " << name << ": " << strerror(-rc) << " (" << rc << ")\n";
        return false;
    }

    return true;
}

static bool pin_required_maps(const options &opts, bpf_object *object)
{
    std::string maps_dir = opts.pin_root + "/" + opts.interface_name + "/" + backend_str(opts.backend) + "/maps";

    if (!mkdir_p(maps_dir, 0755))
    {
        return false;
    }

    static const char *k_maps[] = {"cs_cnt", "cs_blk_icmp", "cs_blk_tcp", "cs_blk_udp"};
    for (const char *m : k_maps)
    {
        if (!pin_one_map(object, maps_dir, m))
        {
            return false;
        }
    }

    std::cout << "Pinned maps under: " << maps_dir << "\n";
    return true;
}

static bool open_object_and_load(const options &opts, bpf_object **out_object, int &out_counters_fd, int &out_prog_fd)
{
    bpf_object *object = bpf_object__open_file(opts.object_path.c_str(), nullptr);
    int object_error = libbpf_get_error(object);
    if (object_error)
    {
        std::cerr << "bpf_object__open_file failed: " << strerror(-object_error) << " (" << object_error << ")\n";
        return false;
    }

    int rc = bpf_object__load(object);
    if (rc != 0)
    {
        print_tc_err("bpf_object__load", rc);
        bpf_object__close(object);
        return false;
    }

    bpf_program *program = nullptr;
    bool program_found = false;

    bpf_program *current = nullptr;
    bpf_object__for_each_program(current, object)
    {
        const char *section = bpf_program__section_name(current);
        if (section && opts.section_name == section)
        {
            program = current;
            program_found = true;
            break;
        }
    }

    if (!program_found)
    {
        std::cerr << "Program section not found: " << opts.section_name << "\n";
        bpf_object__close(object);
        return false;
    }

    int program_fd = bpf_program__fd(program);
    if (program_fd < 0)
    {
        std::cerr << "bpf_program__fd failed\n";
        bpf_object__close(object);
        return false;
    }

    bpf_map *counters_map = bpf_object__find_map_by_name(object, "cs_cnt");
    if (!counters_map)
    {
        std::cerr << "Map not found: cs_cnt\n";
        bpf_object__close(object);
        return false;
    }

    int counters_fd = bpf_map__fd(counters_map);
    if (counters_fd < 0)
    {
        std::cerr << "bpf_map__fd failed\n";
        bpf_object__close(object);
        return false;
    }

    if (opts.pin_enabled)
    {
        if (!pin_required_maps(opts, object))
        {
            bpf_object__close(object);
            return false;
        }
    }

    *out_object = object;
    out_counters_fd = counters_fd;
    out_prog_fd = program_fd;
    return true;
}

static void cleanup_tc(int ifindex)
{
    const int tc_handle = 1;
    const int tc_priority = 1;

    auto destroy_hook = [&](enum bpf_tc_attach_point ap)
    {
        struct bpf_tc_hook tmp = {};
        init_tc_hook(tmp, ifindex, ap);
        int rc = bpf_tc_hook_destroy(&tmp);
        if (rc != 0 && !is_tc_absent_rc(rc) && rc != -EBUSY)
        {
            print_tc_err("bpf_tc_hook_destroy", rc);
        }
        else if (rc == -EBUSY)
        {
            std::cerr << "bpf_tc_hook_destroy: busy\n";
        }
    };

    auto detach_filter = [&](enum bpf_tc_attach_point ap)
    {
        struct bpf_tc_hook tmp_hook = {};
        init_tc_hook(tmp_hook, ifindex, ap);

        struct bpf_tc_opts tmp_opts = {};
        init_tc_opts(tmp_opts, tc_handle, tc_priority);

        int rc = bpf_tc_detach(&tmp_hook, &tmp_opts);
        if (rc != 0 && !is_tc_absent_rc(rc))
        {
            print_tc_err("bpf_tc_detach", rc);
        }
    };

    detach_filter(BPF_TC_INGRESS);
    detach_filter(BPF_TC_EGRESS);

    destroy_hook(BPF_TC_INGRESS);
    destroy_hook(BPF_TC_EGRESS);
}

static uint32_t xdp_flags_for_mode(const options &opts)
{
    uint32_t flags = 0;
    if (opts.xdp_mode_kind == xdp_mode::generic)
    {
        flags |= XDP_FLAGS_SKB_MODE;
    }
    else
    {
        flags |= XDP_FLAGS_DRV_MODE;
    }
    return flags;
}

int main(int argc, char **argv)
{
    options opts;
    if (!parse_args(argc, argv, opts))
    {
        print_usage(argv[0]);
        return 2;
    }

    libbpf_set_print(libbpf_print);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (set_memlock_unlimited() != 0)
    {
        std::cerr << "setrlimit(RLIMIT_MEMLOCK) failed: " << strerror(errno) << "\n";
        return 1;
    }

    unsigned int ifindex_u = if_nametoindex(opts.interface_name.c_str());
    if (ifindex_u == 0)
    {
        std::cerr << "Unknown interface: " << opts.interface_name << "\n";
        return 1;
    }

    int ifindex = (int)ifindex_u;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (opts.detach_only)
    {
        if (opts.backend == backend_kind::tc)
        {
            cleanup_tc(ifindex);
            std::cout << "Detached tc from " << opts.interface_name << "\n";
            return 0;
        }

        uint32_t flags = xdp_flags_for_mode(opts);
        int rc = bpf_set_link_xdp_fd(ifindex, -1, flags);
        if (rc != 0 && rc != -ENOENT && rc != -EINVAL)
        {
            std::cerr << "xdp detach failed: " << strerror(-rc) << " (" << rc << ")\n";
            return 1;
        }
        std::cout << "Detached xdp (" << xdp_mode_str(opts.xdp_mode_kind) << ") from " << opts.interface_name << "\n";
        return 0;
    }

    bpf_object *object = nullptr;
    int counters_fd = -1;
    int program_fd = -1;

    if (!open_object_and_load(opts, &object, counters_fd, program_fd))
    {
        return 1;
    }

    if (opts.backend == backend_kind::tc)
    {
        cleanup_tc(ifindex);

        const int tc_handle = 1;
        const int tc_priority = 1;

        struct bpf_tc_hook hook = {};
        init_tc_hook(hook, ifindex, BPF_TC_INGRESS);

        int rc = bpf_tc_hook_create(&hook);
        if (rc != 0 && rc != -EEXIST)
        {
            print_tc_err("bpf_tc_hook_create", rc);
            bpf_object__close(object);
            cleanup_tc(ifindex);
            return 1;
        }

        struct bpf_tc_opts tc_opts = {};
        init_tc_opts(tc_opts, tc_handle, tc_priority);
        tc_opts.prog_fd = program_fd;
        tc_opts.flags = BPF_TC_F_REPLACE;

        rc = bpf_tc_attach(&hook, &tc_opts);
        if (rc != 0)
        {
            print_tc_err("bpf_tc_attach", rc);
            bpf_object__close(object);
            cleanup_tc(ifindex);
            return 1;
        }

        std::cout << "Attached tc ingress to " << opts.interface_name
                  << " (obj=" << opts.object_path << ", sec=" << opts.section_name << ")\n";
        std::cout.flush();

        while (!g_should_exit)
        {
            uint64_t passed = read_percpu_counter_sum(counters_fd, 0);
            uint64_t dropped = read_percpu_counter_sum(counters_fd, 1);

            std::cout << "passed=" << passed << " dropped=" << dropped << "\n";
            std::cout.flush();

            if (opts.print_once)
            {
                break;
            }

            usleep((useconds_t)opts.interval_ms * 1000);
        }

        struct bpf_tc_opts detach_opts = {};
        init_tc_opts(detach_opts, tc_handle, tc_priority);

        rc = bpf_tc_detach(&hook, &detach_opts);
        if (rc != 0 && !is_tc_absent_rc(rc))
        {
            print_tc_err("bpf_tc_detach", rc);
        }

        cleanup_tc(ifindex);
        bpf_object__close(object);
        std::cout << "Stopped\n";
        return 0;
    }

    uint32_t flags = xdp_flags_for_mode(opts);

    (void)bpf_set_link_xdp_fd(ifindex, -1, flags);

    int rc = bpf_set_link_xdp_fd(ifindex, program_fd, flags);
    if (rc != 0)
    {
        std::cerr << "xdp attach failed: " << strerror(-rc) << " (" << rc << ")\n";
        bpf_object__close(object);
        return 1;
    }

    std::cout << "Attached xdp (" << xdp_mode_str(opts.xdp_mode_kind) << ") to " << opts.interface_name
              << " (obj=" << opts.object_path << ", sec=" << opts.section_name << ")\n";
    std::cout.flush();

    while (!g_should_exit)
    {
        uint64_t passed = read_percpu_counter_sum(counters_fd, 0);
        uint64_t dropped = read_percpu_counter_sum(counters_fd, 1);

        std::cout << "passed=" << passed << " dropped=" << dropped << "\n";
        std::cout.flush();

        if (opts.print_once)
        {
            break;
        }

        usleep((useconds_t)opts.interval_ms * 1000);
    }

    rc = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (rc != 0 && rc != -ENOENT && rc != -EINVAL)
    {
        std::cerr << "xdp detach failed: " << strerror(-rc) << " (" << rc << ")\n";
    }

    bpf_object__close(object);
    std::cout << "Stopped\n";
    return 0;
}
