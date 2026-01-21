#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <unistd.h>
#include <signal.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <initializer_list>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "policy/scheme.h"

static void die(const std::string &msg);

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
    if (sz && !f.read((char *)b.data(), sz)) die("read failed: " + path);
    return b;
}

static void write_file_all(const std::string &path, const std::vector<uint8_t> &b)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) die("cannot write: " + path);
    if (!b.empty()) f.write((const char *)b.data(), (std::streamsize)b.size());
    if (!f) die("write failed: " + path);
}

static volatile sig_atomic_t g_stop = 0;

static void handle_sig(int)
{
    g_stop = 1;
}

static void maybe_reexec_with_sudo(int argc, char **argv)
{
    if (geteuid() == 0) return;

    std::vector<char *> a;
    a.reserve((size_t)argc + 3);
    a.push_back((char *)"sudo");
    a.push_back((char *)"-E");
    for (int i = 0; i < argc; ++i) a.push_back(argv[i]);
    a.push_back(nullptr);

    execvp("sudo", a.data());
    std::cerr << "exec sudo failed: " << strerror(errno) << "\n";
    exit(1);
}

static void die(const std::string &msg)
{
    std::cerr << "cindersentinel: " << msg << "\n";
    exit(2);
}

static bool is_alias(const std::string &s, const std::initializer_list<const char *> xs)
{
    for (auto x : xs) if (s == x) return true;
    return false;
}

static int find_map_fd_by_name_best_effort(const std::string &name, uint32_t *out_id = nullptr)
{
    uint32_t id = 0, next = 0;
    int best_fd = -1;
    uint32_t best_id = 0;
    int matches = 0;

    while (bpf_map_get_next_id(id, &next) == 0)
    {
        int fd = bpf_map_get_fd_by_id(next);
        if (fd < 0) { id = next; continue; }

        bpf_map_info info {};
        uint32_t len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0)
        {
            close(fd);
            id = next;
            continue;
        }

        if (name == info.name)
        {
            matches++;
            if (next >= best_id)
            {
                if (best_fd >= 0) close(best_fd);
                best_fd = fd;
                best_id = next;
            }
            else
            {
                close(fd);
            }
        }
        else
        {
            close(fd);
        }

        id = next;
    }

    if (best_fd < 0) return -1;
    if (out_id) *out_id = best_id;

    if (matches > 1)
    {
        std::cerr << "cindersentinel: warning: multiple maps named '" << name
                  << "', using id " << best_id << "\n";
    }

    return best_fd;
}

static int open_map_checked(const std::string &name, bpf_map_type type, uint32_t key_sz, uint32_t val_sz)
{
    uint32_t id = 0;
    int fd = find_map_fd_by_name_best_effort(name, &id);
    if (fd < 0)
    {
        die("map '" + name + "' not found. Is dataplane attached? (run ./scripts/dev.sh tc or xdp-on)");
    }

    bpf_map_info info {};
    uint32_t len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0)
    {
        close(fd);
        die("bpf_obj_get_info_by_fd failed for map '" + name + "': " + std::string(strerror(errno)));
    }

    if ((bpf_map_type)info.type != type || info.key_size != key_sz || info.value_size != val_sz)
    {
        std::cerr << "cindersentinel: map '" << name << "' has unexpected shape: "
                  << "type=" << info.type << " key=" << info.key_size << " value=" << info.value_size
                  << " (expected type=" << (int)type << " key=" << key_sz << " value=" << val_sz << ")\n";
        close(fd);
        exit(2);
    }

    return fd;
}

static uint64_t read_percpu_sum_u64(int map_fd, uint32_t key)
{
    int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0) return 0;

    std::vector<uint64_t> per_cpu((size_t)cpu_count, 0);
    if (bpf_map_lookup_elem(map_fd, &key, per_cpu.data()) != 0) return 0;

    uint64_t sum = 0;
    for (int i = 0; i < cpu_count; ++i) sum += per_cpu[(size_t)i];
    return sum;
}

static std::vector<uint16_t> dump_port_set(int map_fd)
{
    std::vector<uint16_t> ports;
    uint16_t cur = 0, next = 0;
    bool has_cur = false;

    while (true)
    {
        void *curp = has_cur ? (void *)&cur : nullptr;
        int rc = bpf_map_get_next_key(map_fd, curp, &next);
        if (rc != 0) break;
        ports.push_back(next);
        cur = next;
        has_cur = true;
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

static void print_ports_line(const std::string &title, const std::vector<uint16_t> &ports)
{
    std::cout << title;
    if (ports.empty())
    {
        std::cout << "none\n";
        return;
    }
    for (size_t i = 0; i < ports.size(); ++i)
    {
        if (i) std::cout << ",";
        std::cout << ports[i];
    }
    std::cout << "\n";
}

static uint16_t parse_port(const std::string &s)
{
    char *end = nullptr;
    long v = strtol(s.c_str(), &end, 10);
    if (!s.size() || (end && *end)) die("bad port: " + s);
    if (v < 1 || v > 65535) die("port out of range: " + s);
    return (uint16_t)v;
}

static void cmd_aura()
{
    int fd_icmp = open_map_checked("cs_blk_icmp", BPF_MAP_TYPE_ARRAY, 4, 1);
    int fd_tcp  = open_map_checked("cs_blk_tcp",  BPF_MAP_TYPE_HASH,  2, 1);
    int fd_udp  = open_map_checked("cs_blk_udp",  BPF_MAP_TYPE_HASH,  2, 1);

    uint32_t k0 = 0;
    uint8_t v = 0;
    (void)bpf_map_lookup_elem(fd_icmp, &k0, &v);

    std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";

    auto tcp = dump_port_set(fd_tcp);
    auto udp = dump_port_set(fd_udp);

    print_ports_line("tcp_forbidden: ", tcp);
    print_ports_line("udp_forbidden: ", udp);

    close(fd_icmp);
    close(fd_tcp);
    close(fd_udp);
}

static void cmd_embers(bool watch, int interval_ms)
{
    int fd_cnt = open_map_checked("cs_cnt", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8);

    auto print_once = [&]()
    {
        uint64_t passed = read_percpu_sum_u64(fd_cnt, 0);
        uint64_t dropped_total = read_percpu_sum_u64(fd_cnt, 1);
        uint64_t drop_icmp = read_percpu_sum_u64(fd_cnt, 2);
        uint64_t drop_tcp = read_percpu_sum_u64(fd_cnt, 3);
        uint64_t drop_udp = read_percpu_sum_u64(fd_cnt, 4);

        std::cout
            << "passed=" << passed
            << " dropped=" << dropped_total
            << " drop_icmp=" << drop_icmp
            << " drop_tcp_port=" << drop_tcp
            << " drop_udp_port=" << drop_udp
            << "\n";
    };

    if (!watch)
    {
        print_once();
        close(fd_cnt);
        return;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (!g_stop)
    {
        print_once();
        usleep((useconds_t)interval_ms * 1000u);
    }

    close(fd_cnt);
}

static void cmd_etch(int argc, char **argv)
{
    if (argc < 1) die("etch: missing target (icmp|tcp|udp)");

    std::string target = argv[0];
    if (target != "icmp" && target != "tcp" && target != "udp")
        die("etch: bad target: " + target);

    if (argc < 2) die("etch: missing action");

    std::string act = argv[1];

    if (target == "icmp")
    {
        int fd = open_map_checked("cs_blk_icmp", BPF_MAP_TYPE_ARRAY, 4, 1);
        uint32_t k0 = 0;

        if (is_alias(act, {"forbid","on"}))
        {
            uint8_t v = 1;
            if (bpf_map_update_elem(fd, &k0, &v, BPF_ANY) != 0)
                die("icmp forbid failed: " + std::string(strerror(errno)));
        }
        else if (is_alias(act, {"let","off"}))
        {
            uint8_t v = 0;
            if (bpf_map_update_elem(fd, &k0, &v, BPF_ANY) != 0)
                die("icmp let failed: " + std::string(strerror(errno)));
        }
        else if (act == "show")
        {
            uint8_t v = 0;
            (void)bpf_map_lookup_elem(fd, &k0, &v);
            std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";
        }
        else
        {
            die("etch icmp: action must be forbid|let|show (aliases: on/off)");
        }

        close(fd);
        return;
    }

    if (act == "show")
    {
        int fd = open_map_checked(target == "tcp" ? "cs_blk_tcp" : "cs_blk_udp",
                                BPF_MAP_TYPE_HASH, 2, 1);
        auto ports = dump_port_set(fd);
        print_ports_line(target + std::string("_forbidden: "), ports);
        close(fd);
        return;
    }

    if (argc < 3) die("etch " + target + ": missing port");
    uint16_t port = parse_port(argv[2]);

    int fd = open_map_checked(target == "tcp" ? "cs_blk_tcp" : "cs_blk_udp",
                            BPF_MAP_TYPE_HASH, 2, 1);

    if (is_alias(act, {"forbid","block"}))
    {
        uint8_t v = 1;
        if (bpf_map_update_elem(fd, &port, &v, BPF_ANY) != 0)
            die(target + " forbid failed: " + std::string(strerror(errno)));
    }
    else if (is_alias(act, {"let","unblock"}))
    {
        int rc = bpf_map_delete_elem(fd, &port);
        if (rc != 0 && errno != ENOENT)
            die(target + " let failed: " + std::string(strerror(errno)));
    }
    else
    {
        die("etch " + target + ": action must be forbid|let|show (aliases: block/unblock)");
    }

    close(fd);
}

static void cmd_try(int argc, char **argv)
{
    if (argc < 1) die("try: missing <policy.cbor>");
    std::string in_path = argv[0];

    std::string out_path;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--out")
        {
            if (i + 1 >= argc) die("try: --out requires path");
            out_path = argv[++i];
        }
        else
        {
            die("try: unknown arg: " + a);
        }
    }

    auto bytes = read_file_all(in_path);

    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    cs::policy_error err;
    if (!cs::policy_parse_validate_canonical(bytes, canon, sum, err))
        die("policy invalid: " + err.msg);

    bool same = (bytes == canon);

    if (!out_path.empty())
    {
        write_file_all(out_path, canon);
        std::cout << "OK (canonical written): " << out_path << "\n";
    }

    if (!same)
    {
        if (out_path.empty())
            die("policy is valid but not canonical. Re-run with: try <in> --out <out.cbor>");
        return;
    }

    std::cout << "OK (canonical)\n";
    std::cout << cs::policy_aware_text(sum);
}

static void cmd_invoke(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    die("invoke: not implemented yet (Step 3 will apply canonical policy into eBPF maps)");
}

static void cmd_stepback(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    die("stepback: not implemented yet (Step 3 will restore previous policy)");
}

static void cmd_aware(int argc, char **argv)
{
    if (argc < 1) die("aware: missing <policy.cbor>");
    std::string in_path = argv[0];
    auto bytes = read_file_all(in_path);

    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    cs::policy_error err;
    if (!cs::policy_parse_validate_canonical(bytes, canon, sum, err))
        die("policy invalid: " + err.msg);

    bool same = (bytes == canon);
    if (!same)
        std::cout << "warning: input is not canonical (use: try <in> --out <out.cbor>)\n";

    std::cout << cs::policy_aware_text(sum);
}

static void usage(const char *argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " etch icmp forbid|let|show\n"
        << "  " << argv0 << " etch tcp  forbid|let|show [port]\n"
        << "  " << argv0 << " etch udp  forbid|let|show [port]\n"
        << "  " << argv0 << " aura\n"
        << "  " << argv0 << " embers [--watch] [--interval-ms N]\n"
        << "  " << argv0 << " try <policy.cbor> [--out <canonical.cbor>]\n"
        << "  " << argv0 << " invoke <policy.cbor>\n"
        << "  " << argv0 << " stepback\n"
        << "  " << argv0 << " aware <policy.cbor>\n";
}

int main(int argc, char **argv)
{
    maybe_reexec_with_sudo(argc, argv);

    if (argc < 2)
    {
        usage(argv[0]);
        return 2;
    }

    std::string cmd = argv[1];

    if (cmd == "aura")
    {
        cmd_aura();
        return 0;
    }
    if (cmd == "embers")
    {
        bool watch = false;
        int interval_ms = 1000;

        for (int i = 2; i < argc; ++i)
        {
            std::string a = argv[i];
            if (a == "--watch") watch = true;
            else if (a == "--interval-ms")
            {
                if (i + 1 >= argc) die("--interval-ms requires value");
                interval_ms = atoi(argv[++i]);
                if (interval_ms < 10) interval_ms = 10;
            }
            else
            {
                die("unknown embers arg: " + a);
            }
        }

        cmd_embers(watch, interval_ms);
        return 0;
    }
    if (cmd == "etch")
    {
        if (argc < 4)
        {
            usage(argv[0]);
            return 2;
        }
        cmd_etch(argc - 2, argv + 2);
        return 0;
    }

    if (cmd == "try")
    {
        if (argc < 3)
        {
            usage(argv[0]);
            return 2;
        }
        cmd_try(argc - 2, argv + 2);
        return 0;
    }
    if (cmd == "invoke")
    {
        if (argc < 3)
        {
            usage(argv[0]);
            return 2;
        }
        cmd_invoke(argc - 2, argv + 2);
        return 0;
    }
    if (cmd == "stepback")
    {
        cmd_stepback(argc - 2, argv + 2);
        return 0;
    }
    if (cmd == "aware")
    {
        if (argc < 3)
        {
            usage(argv[0]);
            return 2;
        }
        cmd_aware(argc - 2, argv + 2);
        return 0;
    }

    usage(argv[0]);
    return 2;
}
