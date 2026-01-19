#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static volatile sig_atomic_t g_should_exit = 0;

static void HandleSignal(int)
{
    g_should_exit = 1;
}

static int SetMemlockUnlimited()
{
    rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    return setrlimit(RLIMIT_MEMLOCK, &limit);
}

static int LibbpfPrint(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

struct Options
{
    std::string interface_name;
    std::string object_path = "build/cindersentinel_tc.bpf.o";
    std::string section_name = "classifier";
    int interval_ms = 1000;
    bool detach_only = false;
    bool print_once = false;
};

static void PrintUsage(const char *argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " --iface <ifname> [--obj <path>] [--sec <section>] [--interval-ms <n>] [--once]\n"
        << "  " << argv0 << " --iface <ifname> [--obj <path>] [--sec <section>] --detach\n";
}

static bool ParseInt(const char *s, int &out)
{
    char *end = nullptr;
    long v = strtol(s, &end, 10);
    if (!s[0] || (end && *end)) return false;
    if (v < 0 || v > 3600 * 1000) return false;
    out = (int)v;
    return true;
}

static bool ParseArgs(int argc, char **argv, Options &options)
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
            if (!v) return false;
            options.interface_name = v;
        }
        else if (a == "--obj")
        {
            const char *v = need_value("--obj");
            if (!v) return false;
            options.object_path = v;
        }
        else if (a == "--sec")
        {
            const char *v = need_value("--sec");
            if (!v) return false;
            options.section_name = v;
        }
        else if (a == "--interval-ms")
        {
            const char *v = need_value("--interval-ms");
            if (!v) return false;
            if (!ParseInt(v, options.interval_ms))
            {
                std::cerr << "Bad --interval-ms value\n";
                return false;
            }
        }
        else if (a == "--detach")
        {
            options.detach_only = true;
        }
        else if (a == "--once")
        {
            options.print_once = true;
        }
        else if (a == "-h" || a == "--help")
        {
            PrintUsage(argv[0]);
            exit(0);
        }
        else
        {
            std::cerr << "Unknown argument: " << a << "\n";
            return false;
        }
    }

    if (options.interface_name.empty())
    {
        std::cerr << "--iface is required\n";
        return false;
    }

    return true;
}

static uint64_t ReadPerCpuCounterSum(int map_fd, uint32_t key)
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

int main(int argc, char **argv)
{
    Options options;
    if (!ParseArgs(argc, argv, options))
    {
        PrintUsage(argv[0]);
        return 2;
    }

    libbpf_set_print(LibbpfPrint);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (SetMemlockUnlimited() != 0)
    {
        std::cerr << "setrlimit(RLIMIT_MEMLOCK) failed: " << strerror(errno) << "\n";
        return 1;
    }

    unsigned int ifindex = if_nametoindex(options.interface_name.c_str());
    if (ifindex == 0)
    {
        std::cerr << "Unknown interface: " << options.interface_name << "\n";
        return 1;
    }

    signal(SIGINT, HandleSignal);
    signal(SIGTERM, HandleSignal);
    struct bpf_tc_hook hook = {};

    hook.sz = sizeof(hook);
    hook.ifindex = (int)ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    bpf_tc_hook_destroy(&hook);

    int rc = bpf_tc_hook_create(&hook);

    if (rc != 0 && rc != -EEXIST)
    {
        std::cerr << "bpf_tc_hook_create failed: " << rc << "\n";
        return 1;
    }

    struct bpf_tc_opts tc_opts = {};
    tc_opts.sz = sizeof(tc_opts);
    tc_opts.handle = 1;
    tc_opts.priority = 1;

    if (options.detach_only)
    {
        rc = bpf_tc_detach(&hook, &tc_opts);
        if (rc != 0)
        {
            std::cerr << "bpf_tc_detach failed: " << rc << "\n";
            return 1;
        }
        std::cout << "Detached from " << options.interface_name << "\n";
        return 0;
    }

    bpf_object *object = bpf_object__open_file(options.object_path.c_str(), nullptr);
    int object_error = libbpf_get_error(object);
    if (object_error)
    {
        std::cerr << "bpf_object__open_file failed: " << strerror(-object_error) << " (" << object_error << ")\n";
        return 1;
    }


    rc = bpf_object__load(object);
    if (rc != 0)
    {
        std::cerr << "bpf_object__load failed: " << rc << "\n";
        bpf_object__close(object);
        return 1;
    }

    bpf_program *program = nullptr;
    bool program_found = false;

    bpf_program *current = nullptr;
    bpf_object__for_each_program(current, object)
    {
        const char *section = bpf_program__section_name(current);
        if (section && options.section_name == section)
        {
            program = current;
            program_found = true;
            break;
        }
    }

    if (!program_found)
    {
        std::cerr << "Program section not found: " << options.section_name << "\n";
        bpf_object__close(object);
        return 1;
    }

    int program_fd = bpf_program__fd(program);
    if (program_fd < 0)
    {
        std::cerr << "bpf_program__fd failed\n";
        bpf_object__close(object);
        return 1;
    }

    bpf_map *counters_map = bpf_object__find_map_by_name(object, "cs_cnt");
    if (!counters_map)
    {
        std::cerr << "Map not found: cs_cnt\n";
        bpf_object__close(object);
        return 1;
    }

    int counters_fd = bpf_map__fd(counters_map);
    if (counters_fd < 0)
    {
        std::cerr << "bpf_map__fd failed\n";
        bpf_object__close(object);
        return 1;
    }

    tc_opts.prog_fd = program_fd;
    tc_opts.flags = BPF_TC_F_REPLACE;

    rc = bpf_tc_attach(&hook, &tc_opts);
    if (rc != 0)
    {
        std::cerr << "bpf_tc_attach failed: " << rc << "\n";
        bpf_object__close(object);
        return 1;
    }

    std::cout << "Attached TC ingress to " << options.interface_name
              << " (obj=" << options.object_path << ", sec=" << options.section_name << ")\n";

    while (!g_should_exit)
    {
        uint64_t passed = ReadPerCpuCounterSum(counters_fd, 0);
        uint64_t dropped = ReadPerCpuCounterSum(counters_fd, 1);

        std::cout << "passed=" << passed << " dropped=" << dropped << "\n";
        std::cout.flush();

        if (options.print_once) break;

        usleep((useconds_t)options.interval_ms * 1000);
    }

    bpf_tc_opts detach_opts = {};
    detach_opts.sz = sizeof(detach_opts);
    detach_opts.handle = tc_opts.handle;
    detach_opts.priority = tc_opts.priority;

    rc = bpf_tc_detach(&hook, &detach_opts);
    if (rc != 0 && rc != -ENOENT)
    {
        std::cerr << "bpf_tc_detach failed: " << strerror(-rc) << " (" << rc << ")\n";
    }

    bpf_tc_hook_destroy(&hook);

    bpf_object__close(object);
    std::cout << "Stopped\n";
    return 0;
}
