#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <initializer_list>

#include <iostream>
#include <string>
#include <vector>

#include "policy/scheme.h"
#include "policy/maps_pins.h"
#include "policy/hash.h"
#include "policy/state_store.h"
#include "policy/apply.h"
#include "policy/policy.h"

#include "maps/maps.h"
#include "runtime/runtime.h"
#include "io_utils/io_utils.h"

using cs::io_utils::die;
using cs::io_utils::write_all_fd;

using cs::maps::dump_port_set;
using cs::maps::open_pinned_maps_for_backend;
using cs::maps::parse_port;
using cs::maps::print_ports_line;
using cs::maps::read_percpu_sum_u64;

static void run_aegis_gate(const std::vector<uint8_t> &canon)
{
    char tmp[] = "/tmp/cindersentinel-aegis.XXXXXX";
    int fd = ::mkstemp(tmp);
    if (fd < 0) die("aegis: mkstemp failed: " + std::string(strerror(errno)));

    if (!canon.empty() && write_all_fd(fd, canon.data(), canon.size()) != 0)
    {
        int e = errno;
        ::close(fd);
        ::unlink(tmp);
        errno = e;
        die("aegis: write failed: " + std::string(strerror(errno)));
    }

    if (::close(fd) != 0)
    {
        int e = errno;
        ::unlink(tmp);
        errno = e;
        die("aegis: close failed: " + std::string(strerror(errno)));
    }

    pid_t pid = ::fork();
    if (pid < 0)
    {
        ::unlink(tmp);
        die("aegis: fork failed: " + std::string(strerror(errno)));
    }
    if (pid == 0)
    {
        const char *env_bin = std::getenv("CINDERSENTINEL_AEGIS");
        const char *bin = "cindersentinel-aegis";
        if (geteuid() != 0 && env_bin && *env_bin)
        {
            bin = env_bin;
        }
        ::execlp(bin, bin, tmp, (char *)nullptr);
        _exit(127);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0)
    {
        ::unlink(tmp);
        die("aegis: waitpid failed: " + std::string(strerror(errno)));
    }

    ::unlink(tmp);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        die("aegis: gate failed (exit " + std::to_string(code) + ")");
    }
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
    for (int i = 0; i < argc; ++i) a.push_back(argv[i]);
    a.push_back(nullptr);

    execvp("sudo", a.data());
    std::cerr << "exec sudo failed: " << strerror(errno) << "\n";
    exit(1);
}



using runtime_backend = cs::runtime::runtime_backend;
using runtime_opts = cs::runtime::runtime_opts;
using backend_view = cs::runtime::backend_view;



static void cmd_aura_from_maps(const cs::maps_fds &fds, const char *label, bool show_label)
{
    if (show_label) std::cout << "backend=" << label << "\n";

    uint32_t k0 = 0;
    uint8_t v = 0;
    (void)bpf_map_lookup_elem(fds.fd_blk_icmp, &k0, &v);

    uint8_t v_frag = 0;
    (void)bpf_map_lookup_elem(fds.fd_blk_ipv4_frag, &k0, &v_frag);

    uint8_t v_encap = 0;
    (void)bpf_map_lookup_elem(fds.fd_blk_ipv4_encap, &k0, &v_encap);

    std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";
    std::cout << "ipv4_frag: " << (v_frag ? "let" : "drop") << "\n";
    std::cout << "ipv4_encap: " << (v_encap ? "let" : "drop") << "\n";

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
        have_tc = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::XDP, xdp_fds, err_xdp);

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
    uint64_t drop_ipv4_frag = read_percpu_sum_u64(fds.fd_cnt, 5);
    uint64_t drop_ipv4_encap = read_percpu_sum_u64(fds.fd_cnt, 6);
    uint64_t drop_invalid_l4 = read_percpu_sum_u64(fds.fd_cnt, 7);
    uint64_t drop_invalid_tcp_header = read_percpu_sum_u64(fds.fd_cnt, 8);
    uint64_t drop_invalid_udp_length = read_percpu_sum_u64(fds.fd_cnt, 9);

    if (show_label) std::cout << "backend=" << label << " ";

    std::cout
        << "passed=" << passed
        << " dropped=" << dropped_total
        << " drop_icmp=" << drop_icmp
        << " drop_tcp_port=" << drop_tcp
        << " drop_udp_port=" << drop_udp
        << " drop_ipv4_frag=" << drop_ipv4_frag
        << " drop_ipv4_encap=" << drop_ipv4_encap
        << " drop_invalid_l4=" << drop_invalid_l4
        << " drop_invalid_tcp_header=" << drop_invalid_tcp_header
        << " drop_invalid_udp_length=" << drop_invalid_udp_length
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
        have_tc = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::XDP, xdp_fds, err_xdp);

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
    if (args.size() < 1) die("etch: missing target (icmp|tcp|udp|ipv4_frag|ipv4_encap)");

    std::string target = args[0];
    if (target != "icmp" && target != "tcp" && target != "udp" && target != "ipv4_frag" && target != "ipv4_encap")
        die("etch: bad target: " + target);

    if (args.size() < 2) die("etch: missing action");

    std::string act = args[1];
    bool mutated = false;

    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::XDP, xdp_fds, err_xdp);

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

    auto apply_mutation_atomic = [&](auto mutate, const char *ctx)
    {
        cs::apply_error ae;

        struct backend_state
        {
            const char *label;
            cs::maps_fds *fds;
            cs::runtime_state old_state;
            cs::runtime_state new_state;
            bool applied = false;
        };

        std::vector<backend_state> states;
        states.reserve(backends.size());

        for (auto &b : backends)
        {
            backend_state st { b.label, b.fds, {}, {}, false };
            if (cs::read_runtime_state(*b.fds, st.old_state, ae) != 0)
                die(std::string(ctx) + ": " + ae.msg);
            st.new_state = st.old_state;
            mutate(st.new_state);
            states.push_back(std::move(st));
        }

        for (auto &st : states)
        {
            if (cs::apply_delta(*st.fds, st.old_state, st.new_state, ae) != 0)
            {
                for (auto &rb : states)
                {
                    if (!rb.applied) break;
                    (void)cs::apply_delta(*rb.fds, rb.new_state, rb.old_state, ae);
                }
                die(std::string(ctx) + ": " + ae.msg);
            }
            st.applied = true;
        }
    };

    if (target == "ipv4_frag")
    {
        if (act == "show")
        {
            for (auto &b : backends)
            {
                uint32_t k0 = 0;
                uint8_t v = 0;
                (void)bpf_map_lookup_elem(b.fds->fd_blk_ipv4_frag, &k0, &v);
                if (show_label) std::cout << "backend=" << b.label << "\n";
                std::cout << "ipv4_frag: " << (v ? "let" : "drop") << "\n";
            }
            return;
        }

        if (cs::runtime::is_alias(act, {"drop","forbid","on"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.ipv4_frag_drop = true;
            }, "etch ipv4_frag");
            mutated = true;
        }
        else if (cs::runtime::is_alias(act, {"let","pass","off"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.ipv4_frag_drop = false;
            }, "etch ipv4_frag");
            mutated = true;
        }
        else
        {
            die("etch ipv4_frag: action must be drop|let|show (aliases: forbid/on, pass/off)");
        }

        if (mutated)
        {
            std::vector<backend_view> views;
            views.reserve(backends.size());
            for (auto &b : backends) views.push_back({b.label, b.fds});
            cs::runtime::sync_runtime_to_state(rt, views, "etch");
        }
        return;
    }

    if (target == "ipv4_encap")
    {
        if (act == "show")
        {
            for (auto &b : backends)
            {
                uint32_t k0 = 0;
                uint8_t v = 0;
                (void)bpf_map_lookup_elem(b.fds->fd_blk_ipv4_encap, &k0, &v);
                if (show_label) std::cout << "backend=" << b.label << "\n";
                std::cout << "ipv4_encap: " << (v ? "let" : "drop") << "\n";
            }
            return;
        }

        if (cs::runtime::is_alias(act, {"drop","forbid","on"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.ipv4_encap_drop = true;
            }, "etch ipv4_encap");
            mutated = true;
        }
        else if (cs::runtime::is_alias(act, {"let","pass","off"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.ipv4_encap_drop = false;
            }, "etch ipv4_encap");
            mutated = true;
        }
        else
        {
            die("etch ipv4_encap: action must be drop|let|show (aliases: forbid/on, pass/off)");
        }

        if (mutated)
        {
            std::vector<backend_view> views;
            views.reserve(backends.size());
            for (auto &b : backends) views.push_back({b.label, b.fds});
            cs::runtime::sync_runtime_to_state(rt, views, "etch");
        }
        return;
    }

    if (target == "icmp")
    {
        if (act == "show")
        {
            for (auto &b : backends)
            {
                uint32_t k0 = 0;
                uint8_t v = 0;
                (void)bpf_map_lookup_elem(b.fds->fd_blk_icmp, &k0, &v);
                if (show_label) std::cout << "backend=" << b.label << "\n";
                std::cout << "icmp: " << (v ? "forbid" : "let") << "\n";
            }
            return;
        }

        if (cs::runtime::is_alias(act, {"forbid","on"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.icmp_forbid = true;
            }, "etch icmp");
            mutated = true;
        }
        else if (cs::runtime::is_alias(act, {"let","off"}))
        {
            apply_mutation_atomic([&](cs::runtime_state &st)
            {
                st.icmp_forbid = false;
            }, "etch icmp");
            mutated = true;
        }
        else
        {
            die("etch icmp: action must be forbid|let|show (aliases: on/off)");
        }

        if (mutated)
        {
            std::vector<backend_view> views;
            views.reserve(backends.size());
            for (auto &b : backends) views.push_back({b.label, b.fds});
            cs::runtime::sync_runtime_to_state(rt, views, "etch");
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

    bool forbid = false;
    if (cs::runtime::is_alias(act, {"forbid","block"}))
    {
        forbid = true;
    }
    else if (cs::runtime::is_alias(act, {"let","unblock"}))
    {
        forbid = false;
    }
    else
    {
        die("etch " + target + ": action must be forbid|let|show (aliases: block/unblock)");
    }

    std::string ctx = "etch " + target;
    apply_mutation_atomic([&](cs::runtime_state &st)
    {
        auto &ports = (target == "tcp") ? st.tcp_forbidden_ports : st.udp_forbidden_ports;
        auto it = std::lower_bound(ports.begin(), ports.end(), port);
        if (forbid)
        {
            if (it == ports.end() || *it != port) ports.insert(it, port);
        }
        else
        {
            if (it != ports.end() && *it == port) ports.erase(it);
        }
    }, ctx.c_str());
    mutated = true;

    if (mutated)
    {
        std::vector<backend_view> views;
        views.reserve(backends.size());
        for (auto &b : backends) views.push_back({b.label, b.fds});
        cs::runtime::sync_runtime_to_state(rt, views, "etch");
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

    std::vector<uint8_t> bytes;
    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    bool same = false;
    cs::policy::load_and_canonicalize_policy(in_path, bytes, canon, sum, same);
    run_aegis_gate(canon);

    if (!out_path.empty())
    {
        cs::io_utils::write_file_all(out_path, canon);
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

static void cmd_gate(int argc, char **argv)
{
    if (argc < 1) die("gate: missing <policy.cbor>");
    if (argc > 1) die("gate: unknown arg: " + std::string(argv[1]));

    std::string in_path = argv[0];

    std::vector<uint8_t> canon;
    [[maybe_unused]] cs::policy_summary sum;
    cs::policy::load_canonical_policy(in_path, canon, sum);

    run_aegis_gate(canon);

    std::cout << "OK (gate)\n";
}

static void cmd_invoke(const runtime_opts &rt, const std::vector<std::string> &args)
{
    if (args.empty()) die("invoke: missing <policy.cbor>");
    if (args.size() > 1) die("invoke: unknown arg: " + args[1]);

    std::string in_path = args[0];

    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    cs::policy::load_canonical_policy(in_path, canon, sum);

    run_aegis_gate(canon);

    std::string hash = cs::sha256_hex(canon);

    cs::state_store_opts so;
    so.state_root = rt.state_root;
    cs::state_store store(so, rt.iface);

    cs::state_error se;
    if (store.ensure_dirs(se) != 0) die("state: " + se.msg);

    cs::state_lock lk;
    if (store.lock_exclusive(lk, se) != 0) die("state: " + se.msg);

    if (store.store_policy_blob(hash, canon, se) != 0) die("state: " + se.msg);

    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::XDP, xdp_fds, err_xdp);

    if (rt.backend == runtime_backend::tc)
    {
        if (!have_tc) die("invoke: " + err_tc);
    }
    else if (rt.backend == runtime_backend::xdp)
    {
        if (!have_xdp) die("invoke: " + err_xdp);
    }
    else
    {
        if (!have_tc || !have_xdp)
            die("invoke: backend=all requires pinned maps for both tc and xdp");
    }

    if (rt.backend == runtime_backend::all)
    {
        std::vector<backend_view> views;
        views.reserve(2);
        if (have_tc) views.push_back({"tc", &tc_fds});
        if (have_xdp) views.push_back({"xdp", &xdp_fds});
        cs::runtime::apply_summary_to_backends_atomic(views, sum, "invoke(all)");
    }
    else
    {
        if (have_tc) cs::runtime::apply_summary_to_maps(tc_fds, sum, "invoke(tc)");
        if (have_xdp) cs::runtime::apply_summary_to_maps(xdp_fds, sum, "invoke(xdp)");
    }

    std::vector<std::string> hist;
    if (store.read_history(hist, se) != 0) die("state: " + se.msg);
    store.history_push(hist, hash);
    if (store.write_history(hist, se) != 0) die("state: " + se.msg);

    cs::active_info ai;
    ai.sha256 = hash;
    ai.kind = sum.kind;
    ai.v = sum.v;
    ai.updated_at_ms = cs::runtime::now_ms();
    ai.source = "invoke";
    if (store.write_active(ai, se) != 0) die("state: " + se.msg);

    std::cout << "OK: " << hash << "\n";
    std::cout << cs::policy_aware_text(sum);
}

static void cmd_stepback(const runtime_opts &rt, const std::vector<std::string> &args)
{
    if (!args.empty()) die("stepback: unknown arg: " + args[0]);

    cs::state_store_opts so;
    so.state_root = rt.state_root;
    cs::state_store store(so, rt.iface);

    cs::state_error se;
    if (store.ensure_dirs(se) != 0) die("state: " + se.msg);

    cs::state_lock lk;
    if (store.lock_exclusive(lk, se) != 0) die("state: " + se.msg);

    std::vector<std::string> hist;
    if (store.read_history(hist, se) != 0) die("state: " + se.msg);

    cs::active_info cur;
    int ar = store.read_active(cur, se);
    if (ar == 0)
    {
        if (hist.empty() || hist.back() != cur.sha256)
            die("stepback: history does not match active");
    }
    else if (ar != -ENOENT)
    {
        die("state: " + se.msg);
    }
    else if (!hist.empty())
    {
        die("stepback: history exists but active is missing");
    }

    if (store.history_pop(hist, se) != 0) die("stepback: " + se.msg);

    std::string target = hist.back();

    std::vector<uint8_t> bytes;
    if (store.load_policy_blob(target, bytes, se) != 0) die("state: " + se.msg);

    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    cs::policy_error pe;
    if (!cs::policy_parse_validate_canonical(bytes, canon, sum, pe))
        die("policy invalid: " + pe.msg);

    std::string hash = cs::sha256_hex(canon);
    if (hash != target)
        die("stepback: policy hash mismatch");

    cs::maps_fds tc_fds;
    cs::maps_fds xdp_fds;
    bool have_tc = false;
    bool have_xdp = false;
    std::string err_tc;
    std::string err_xdp;

    if (rt.backend == runtime_backend::tc || rt.backend == runtime_backend::all)
        have_tc = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::TC, tc_fds, err_tc);
    if (rt.backend == runtime_backend::xdp || rt.backend == runtime_backend::all)
        have_xdp = open_pinned_maps_for_backend(rt.pin_base, rt.iface, cs::cs_backend::XDP, xdp_fds, err_xdp);

    if (rt.backend == runtime_backend::tc)
    {
        if (!have_tc) die("stepback: " + err_tc);
    }
    else if (rt.backend == runtime_backend::xdp)
    {
        if (!have_xdp) die("stepback: " + err_xdp);
    }
    else
    {
        if (!have_tc || !have_xdp)
            die("stepback: backend=all requires pinned maps for both tc and xdp");
    }

    if (rt.backend == runtime_backend::all)
    {
        std::vector<backend_view> views;
        views.reserve(2);
        if (have_tc) views.push_back({"tc", &tc_fds});
        if (have_xdp) views.push_back({"xdp", &xdp_fds});
        cs::runtime::apply_summary_to_backends_atomic(views, sum, "stepback(all)");
    }
    else
    {
        if (have_tc) cs::runtime::apply_summary_to_maps(tc_fds, sum, "stepback(tc)");
        if (have_xdp) cs::runtime::apply_summary_to_maps(xdp_fds, sum, "stepback(xdp)");
    }

    if (store.write_history(hist, se) != 0) die("state: " + se.msg);

    cs::active_info ai;
    ai.sha256 = hash;
    ai.kind = sum.kind;
    ai.v = sum.v;
    ai.updated_at_ms = cs::runtime::now_ms();
    ai.source = "stepback";
    if (store.write_active(ai, se) != 0) die("state: " + se.msg);

    std::cout << "OK: " << hash << "\n";
    std::cout << cs::policy_aware_text(sum);
}

static void cmd_aware(int argc, char **argv)
{
    if (argc < 1) die("aware: missing <policy.cbor>");
    std::string in_path = argv[0];
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    bool same = false;
    cs::policy::load_and_canonicalize_policy(in_path, bytes, canon, sum, same);

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
        << "  " << argv0 << " etch ipv4_frag drop|let|show --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " etch ipv4_encap drop|let|show --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " aura --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>]\n"
        << "  " << argv0 << " embers --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>] [--watch] [--interval-ms N]\n"
        << "  " << argv0 << " try <policy.cbor> [--out <canonical.cbor>]\n"
        << "  " << argv0 << " gate <policy.cbor>\n"
        << "  " << argv0 << " invoke <policy.cbor> --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>] [--state-root <path>]\n"
        << "  " << argv0 << " stepback --iface <ifname> [--backend tc|xdp|all] [--pin-base <path>] [--state-root <path>]\n"
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
        cs::runtime::parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("aura: --iface is required");
        if (!rest.empty()) die("unknown aura arg: " + rest[0]);
        cmd_aura(rt);
        return 0;
    }
    if (cmd == "embers")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        cs::runtime::parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("embers: --iface is required");
        cmd_embers(rt, rest);
        return 0;
    }
    if (cmd == "etch")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        cs::runtime::parse_runtime_opts(argc, argv, 2, rt, rest);
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
    if (cmd == "gate")
    {
        if (argc < 3)
        {
            usage(argv[0]);
            return 2;
        }
        cmd_gate(argc - 2, argv + 2);
        return 0;
    }
    if (cmd == "invoke")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        cs::runtime::parse_runtime_opts(argc, argv, 2, rt, rest);
        if (rt.iface.empty()) die("invoke: --iface is required");
        cmd_invoke(rt, rest);
        return 0;
    }
    if (cmd == "stepback")
    {
        runtime_opts rt;
        std::vector<std::string> rest;
        cs::runtime::parse_runtime_opts(argc, argv, 2, rt, rest);
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
