#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <sys/resource.h>
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

struct options
{
    std::string interface_name;
    std::string object_path = "build/cindersentinel_tc.bpf.o";
    std::string section_name = "classifier";
    int interval_ms = 1000;
    bool detach_only = false;
    bool print_once = false;
};

static void print_usage(const char *argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " --iface <ifname> [--obj <path>] [--sec <section>] [--interval-ms <n>] [--once]\n"
        << "  " << argv0 << " --iface <ifname> [--obj <path>] [--sec <section>] --detach\n";
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

        if (a == "--iface")
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
        }
        else if (a == "--sec")
        {
            const char *v = need_value("--sec");
            if (!v)
            {
                return false;
            }
            opts.section_name = v;
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

    if (opts.interface_name.empty())
    {
        std::cerr << "--iface is required\n";
        return false;
    }

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

    const int tc_handle = 1;
    const int tc_priority = 1;

    struct bpf_tc_hook hook = {};
    init_tc_hook(hook, ifindex, BPF_TC_INGRESS);

    struct bpf_tc_opts tc_opts = {};
    init_tc_opts(tc_opts, tc_handle, tc_priority);

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
            std::cerr << "bpf_tc_hook_destroy: busy (" << opts.interface_name << ")\n";
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

    auto cleanup_tc = [&]()
    {
        detach_filter(BPF_TC_INGRESS);
        detach_filter(BPF_TC_EGRESS);

        destroy_hook(BPF_TC_INGRESS);
        destroy_hook(BPF_TC_EGRESS);
    };

    if (opts.detach_only)
    {
        cleanup_tc();
        std::cout << "Detached from " << opts.interface_name << "\n";
        return 0;
    }

    cleanup_tc();

    int rc = bpf_tc_hook_create(&hook);
    if (rc != 0 && rc != -EEXIST)
    {
        print_tc_err("bpf_tc_hook_create", rc);
        return 1;
    }

    bpf_object *object = nullptr;
    bool tc_attached = false;

    object = bpf_object__open_file(opts.object_path.c_str(), nullptr);
    int object_error = libbpf_get_error(object);
    if (object_error)
    {
        std::cerr << "bpf_object__open_file failed: " << strerror(-object_error) << " (" << object_error << ")\n";
        return 1;
    }

    rc = bpf_object__load(object);
    if (rc != 0)
    {
        print_tc_err("bpf_object__load", rc);
        bpf_object__close(object);
        cleanup_tc();
        return 1;
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
        cleanup_tc();
        return 1;
    }

    int program_fd = bpf_program__fd(program);
    if (program_fd < 0)
    {
        std::cerr << "bpf_program__fd failed\n";
        bpf_object__close(object);
        cleanup_tc();
        return 1;
    }

    bpf_map *counters_map = bpf_object__find_map_by_name(object, "cs_cnt");
    if (!counters_map)
    {
        std::cerr << "Map not found: cs_cnt\n";
        bpf_object__close(object);
        cleanup_tc();
        return 1;
    }

    int counters_fd = bpf_map__fd(counters_map);
    if (counters_fd < 0)
    {
        std::cerr << "bpf_map__fd failed\n";
        bpf_object__close(object);
        cleanup_tc();
        return 1;
    }

    tc_opts.prog_fd = program_fd;
    tc_opts.flags = BPF_TC_F_REPLACE;

    rc = bpf_tc_attach(&hook, &tc_opts);
    if (rc != 0)
    {
        print_tc_err("bpf_tc_attach", rc);
        bpf_object__close(object);
        cleanup_tc();
        return 1;
    }

    tc_attached = true;

    std::cout << "Attached TC ingress to " << opts.interface_name
              << " (obj=" << opts.object_path << ", sec=" << opts.section_name << ")\n";

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

    if (tc_attached)
    {
        struct bpf_tc_opts detach_opts = {};
        init_tc_opts(detach_opts, tc_handle, tc_priority);

        rc = bpf_tc_detach(&hook, &detach_opts);
        if (rc != 0 && !is_tc_absent_rc(rc))
        {
            print_tc_err("bpf_tc_detach", rc);
        }
    }

    destroy_hook(BPF_TC_INGRESS);
    destroy_hook(BPF_TC_EGRESS);

    bpf_object__close(object);
    std::cout << "Stopped\n";
    return 0;
}
