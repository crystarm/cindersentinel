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
#include "policy/maps_pins.h"

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

enum class runtime_backend
{
    tc,
    xdp,
    all,
};

struct runtime_opts
{
    std::string iface;
    runtime_backend backend = runtime_backend::all;
    std::string pin_base = "/sys/fs/bpf/cindersentinel";
};

static bool parse_backend_value(const std::string &s, runtime_backend &out)
{
    if (s == "tc")
    {
        out = runtime_backend::tc;
        return true;
    }
    if (s == "xdp")
    {
        out = runtime_backend::xdp;
        return true;
    }
    if (s == "all")
    {
        out = runtime_backend::all;
        return true;
    }
    return false;
}

static void parse_runtime_opts(int argc, char **argv, int start,
                               runtime_opts &out,
                               std::vector<std::string> &rest)
{
    for (int i = start; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--iface")
        {
            if (i + 1 >= argc) die("--iface requires value");
            out.iface = argv[++i];
        }
        else if (a == "--backend")
        {
            if (i + 1 >= argc) die("--backend requires value");
            runtime_backend b;
            if (!parse_backend_value(argv[i + 1], b))
                die("bad --backend value (expected: tc|xdp|all)");
            out.backend = b;
            ++i;
        }
        else if (a == "--pin-base")
        {
            if (i + 1 >= argc) die("--pin-base requires value");
            out.pin_base = argv[++i];
        }
        else
        {
            rest.push_back(a);
        }
    }
}



static bool open_pinned_maps_for_backend(const runtime_opts &rt,
                                         cs::cs_backend backend,
                                         cs::maps_fds &out,
                                         std::string &err)
{
    cs::maps_pins_opts opt;
    opt.pin_base = rt.pin_base;
    opt.iface = rt.iface;
    opt.backend = backend;

    cs::maps_error e;
    if (cs::open_pinned_maps(opt, out, e) != 0)
    {
        err = e.msg;
        return false;
    }

    return true;
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

static void cmd_aura_from_maps(const cs::maps_fds &fds, const char *label, bool show_label)
{
    if (show_label) std::cout << "backend=" << label << "\n";

    uint32_t k0 = 0;
    uint8_t v = 0;
    (void)bpf_map_lookup_elem(fds.fd_blk_icmp, &k0, &v);

    std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";

    auto tcp = dump_port_set(fds.fd_blk_tcp);
    auto udp = dump_port_set(fds.fd_blk_udp);

    print_ports_line("tcp_forbidden: ", tcp);
    print_ports_line("udp_forbidden: ", udp);
}

static void cmd_aura(const runtime_opts &rt)
{
    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt, cs::cs_backend::XDP, xdp_fds, err_xdp);

    if (rt.backend == runtime_backend::tc)
    {
        if (!have_tc) die("aura: " + err_tc);
    }
    else if (rt.backend == runtime_backend::xdp)
    {
        if (!have_xdp) die("aura: " + err_xdp);
    }
    else
    {
        if (!have_tc && !have_xdp)
            die("aura: no pinned maps found for tc or xdp");
        if (!have_tc)
            std::cerr << "cindersentinel: warning: no pinned maps for tc (" << err_tc << ")\n";
        if (!have_xdp)
            std::cerr << "cindersentinel: warning: no pinned maps for xdp (" << err_xdp << ")\n";
    }

    bool show_label = (rt.backend == runtime_backend::all);

    if (have_tc) cmd_aura_from_maps(tc_fds, "tc", show_label);
    if (have_xdp) cmd_aura_from_maps(xdp_fds, "xdp", show_label);
}

static void cmd_embers_from_maps(const cs::maps_fds &fds, const char *label, bool show_label)
{
    uint64_t passed = read_percpu_sum_u64(fds.fd_cnt, 0);
    uint64_t dropped_total = read_percpu_sum_u64(fds.fd_cnt, 1);
    uint64_t drop_icmp = read_percpu_sum_u64(fds.fd_cnt, 2);
    uint64_t drop_tcp = read_percpu_sum_u64(fds.fd_cnt, 3);
    uint64_t drop_udp = read_percpu_sum_u64(fds.fd_cnt, 4);

    if (show_label) std::cout << "backend=" << label << " ";

    std::cout
        << "passed=" << passed
        << " dropped=" << dropped_total
        << " drop_icmp=" << drop_icmp
        << " drop_tcp_port=" << drop_tcp
        << " drop_udp_port=" << drop_udp
        << "\n";
}

static void cmd_embers(const runtime_opts &rt, const std::vector<std::string> &args)
{
    bool watch = false;
    int interval_ms = 1000;

    for (size_t i = 0; i < args.size(); ++i)
    {
        std::string a = args[i];
        if (a == "--watch") watch = true;
        else if (a == "--interval-ms")
        {
            if (i + 1 >= args.size()) die("--interval-ms requires value");
            interval_ms = atoi(args[++i].c_str());
            if (interval_ms < 10) interval_ms = 10;
        }
        else
        {
            die("unknown embers arg: " + a);
        }
    }

    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt, cs::cs_backend::XDP, xdp_fds, err_xdp);

    if (rt.backend == runtime_backend::tc)
    {
        if (!have_tc) die("embers: " + err_tc);
    }
    else if (rt.backend == runtime_backend::xdp)
    {
        if (!have_xdp) die("embers: " + err_xdp);
    }
    else
    {
        if (!have_tc && !have_xdp)
            die("embers: no pinned maps found for tc or xdp");
        if (!have_tc)
            std::cerr << "cindersentinel: warning: no pinned maps for tc (" << err_tc << ")\n";
        if (!have_xdp)
            std::cerr << "cindersentinel: warning: no pinned maps for xdp (" << err_xdp << ")\n";
    }

    bool show_label = (rt.backend == runtime_backend::all);

    auto print_once = [&]()
    {
        if (have_tc) cmd_embers_from_maps(tc_fds, "tc", show_label);
        if (have_xdp) cmd_embers_from_maps(xdp_fds, "xdp", show_label);
    };

    if (!watch)
    {
        print_once();
        return;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (!g_stop)
    {
        print_once();
        usleep((useconds_t)interval_ms * 1000u);
    }
}

static void cmd_etch(const runtime_opts &rt, const std::vector<std::string> &args)
{
    if (args.size() < 1) die("etch: missing target (icmp|tcp|udp)");

    std::string target = args[0];
    if (target != "icmp" && target != "tcp" && target != "udp")
        die("etch: bad target: " + target);

    if (args.size() < 2) die("etch: missing action");

    std::string act = args[1];

    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt, cs::cs_backend::XDP, xdp_fds, err_xdp);

    if (rt.backend == runtime_backend::tc)
    {
        if (!have_tc) die("etch: " + err_tc);
    }
    else if (rt.backend == runtime_backend::xdp)
    {
        if (!have_xdp) die("etch: " + err_xdp);
    }
    else
    {
        if (!have_tc || !have_xdp)
            die("etch: backend=all requires pinned maps for both tc and xdp");
    }

    struct backend_entry
    {
        const char *label;
        cs::maps_fds *fds;
    };

    std::vector<backend_entry> backends;
    if (have_tc) backends.push_back({"tc", &tc_fds});
    if (have_xdp) backends.push_back({"xdp", &xdp_fds});

    bool show_label = backends.size() > 1;

    if (target == "icmp")
    {
        for (auto &b : backends)
        {
            uint32_t k0 = 0;

            if (is_alias(act, {"forbid","on"}))
            {
                uint8_t v = 1;
                if (bpf_map_update_elem(b.fds->fd_blk_icmp, &k0, &v, BPF_ANY) != 0)
                    die(std::string(b.label) + ": icmp forbid failed: " + std::string(strerror(errno)));
            }
            else if (is_alias(act, {"let","off"}))
            {
                uint8_t v = 0;
                if (bpf_map_update_elem(b.fds->fd_blk_icmp, &k0, &v, BPF_ANY) != 0)
                    die(std::string(b.label) + ": icmp let failed: " + std::string(strerror(errno)));
            }
            else if (act == "show")
            {
                uint8_t v = 0;
                (void)bpf_map_lookup_elem(b.fds->fd_blk_icmp, &k0, &v);
                if (show_label) std::cout << "backend=" << b.label << "\n";
                std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";
            }
            else
            {
                die("etch icmp: action must be forbid|let|show (aliases: on/off)");
            }
        }

        return;
    }

    if (act == "show")
    {
        for (auto &b : backends)
        {
            int fd = (target == "tcp") ? b.fds->fd_blk_tcp : b.fds->fd_blk_udp;
            auto ports = dump_port_set(fd);
            if (show_label) std::cout << "backend=" << b.label << "\n";
            print_ports_line(target + std::string("_forbidden: "), ports);
        }
        return;
    }

    if (args.size() < 3) die("etch " + target + ": missing port");
    uint16_t port = parse_port(args[2]);

    for (auto &b : backends)
    {
        int fd = (target == "tcp") ? b.fds->fd_blk_tcp : b.fds->fd_blk_udp;

        if (is_alias(act, {"forbid","block"}))
        {
            uint8_t v = 1;
            if (bpf_map_update_elem(fd, &port, &v, BPF_ANY) != 0)
                die(std::string(b.label) + ": " + target + " forbid failed: " + std::string(strerror(errno)));
        }
        else if (is_alias(act, {"let","unblock"}))
        {
            int rc = bpf_map_delete_elem(fd, &port);
            if (rc != 0 && errno != ENOENT)
                die(std::string(b.label) + ": " + target + " let failed: " + std::string(strerror(errno)));
        }
        else
        {
            die("etch " + target + ": action must be forbid|let|show (aliases: block/unblock)");
        }
    }
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

static void cmd_invoke(const runtime_opts &rt, const std::vector<std::string> &args)
{
    (void)rt;
    if (args.empty()) die("invoke: missing <policy.cbor>");
    if (args.size() > 1) die("invoke: unknown arg: " + args[1]);
    die("invoke: not implemented yet (Step 3 will apply canonical policy into eBPF maps)");
}

static void cmd_stepback(const runtime_opts &rt, const std::vector<std::string> &args)
{
    (void)rt;
    if (!args.empty()) die("stepback: unknown arg: " + args[0]);
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
        << "  " << argv0 << " etch icmp forbid|let|show --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " etch tcp  forbid|let|show [port] --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " etch udp  forbid|let|show [port] --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " aura --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " embers --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>] [--watch] [--interval-ms N]\n"
        << "  " << argv0 << " try <policy.cbor> [--out <canonical.cbor>]\n"
        << "  " << argv0 << " invoke <policy.cbor> --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " stepback --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
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
        runtime_opts rt;
        std::vector<std::string> rest;
        parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("aura: --iface is required");
        if (!rest.empty()) die("unknown aura arg: " + rest[0]);
        cmd_aura(rt);
        return 0;
    }
    if (cmd == "embers")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("embers: --iface is required");
        cmd_embers(rt, rest);
        return 0;
    }
    if (cmd == "etch")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("etch: --iface is required");
        cmd_etch(rt, rest);
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
        runtime_opts rt;
        std::vector<std::string> rest;
        parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("invoke: --iface is required");
        cmd_invoke(rt, rest);
        return 0;
    }
    if (cmd == "stepback")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("stepback: --iface is required");
        cmd_stepback(rt, rest);
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
