#include "runtime.h"

#include <chrono>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "../io_utils/io_utils.h"
#include "../policy/hash.h"
#include "../policy/state_store.h"

namespace cs::runtime
{

using cs::io_utils::die;

bool is_alias(const std::string &s, std::initializer_list<const char *> xs)
{
    for (auto x : xs)
        if (s == x) return true;
    return false;
}

bool parse_backend_value(const std::string &s, runtime_backend &out)
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

void parse_runtime_opts(int argc,
                        char **argv,
                        int start,
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
        else if (a == "--state-root")
        {
            if (i + 1 >= argc) die("--state-root requires value");
            out.state_root = argv[++i];
        }
        else
        {
            rest.push_back(a);
        }
    }
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void apply_summary_to_maps(const cs::maps_fds &maps,
                           const cs::policy_summary &sum,
                           const char *ctx)
{
    cs::apply_limits lim;
    cs::apply_error ae;
    cs::runtime_state old_state;
    cs::runtime_state new_state;

    if (cs::read_runtime_state(maps, old_state, ae) != 0)
        die(std::string(ctx) + ": " + ae.msg);
    if (cs::summary_to_runtime_state(sum, new_state, lim, ae) != 0)
        die(std::string(ctx) + ": " + ae.msg);
    if (cs::apply_delta(maps, old_state, new_state, ae) != 0)
        die(std::string(ctx) + ": " + ae.msg);
}

void apply_summary_to_backends_atomic(const std::vector<backend_view> &backends,
                                      const cs::policy_summary &sum,
                                      const char *ctx)
{
    cs::apply_limits lim;
    cs::apply_error ae;
    cs::runtime_state new_state;

    if (cs::summary_to_runtime_state(sum, new_state, lim, ae) != 0)
        die(std::string(ctx) + ": " + ae.msg);

    struct backend_state
    {
        const char *label;
        const cs::maps_fds *fds;
        cs::runtime_state old_state;
        bool applied = false;
    };

    std::vector<backend_state> states;
    states.reserve(backends.size());

    for (const auto &b : backends)
    {
        backend_state st { b.label, b.fds, {}, false };
        if (cs::read_runtime_state(*b.fds, st.old_state, ae) != 0)
            die(std::string(ctx) + ": " + ae.msg);
        states.push_back(std::move(st));
    }

    for (auto &st : states)
    {
        if (cs::apply_delta(*st.fds, st.old_state, new_state, ae) != 0)
        {
            for (auto &rb : states)
            {
                if (!rb.applied) break;
                (void)cs::apply_delta(*rb.fds, new_state, rb.old_state, ae);
            }
            die(std::string(ctx) + ": " + ae.msg);
        }
        st.applied = true;
    }
}

bool runtime_state_equal(const cs::runtime_state &a, const cs::runtime_state &b)
{
    return a.icmp_forbid == b.icmp_forbid &&
           a.ipv4_frag_drop == b.ipv4_frag_drop &&
           a.ipv4_encap_drop == b.ipv4_encap_drop &&
           a.tcp_forbidden_ports == b.tcp_forbidden_ports &&
           a.udp_forbidden_ports == b.udp_forbidden_ports;
}

void sync_runtime_to_state(const runtime_opts &rt,
                           const std::vector<backend_view> &backends,
                           const std::string &source)
{
    if (backends.empty()) die("sync: no backends available");

    cs::state_store_opts so;
    so.state_root = rt.state_root;
    cs::state_store store(so, rt.iface);

    cs::state_error se;
    if (store.ensure_dirs(se) != 0) die("state: " + se.msg);

    cs::state_lock lk;
    if (store.lock_exclusive(lk, se) != 0) die("state: " + se.msg);

    cs::apply_error ae;
    cs::runtime_state st;
    if (cs::read_runtime_state(*backends[0].fds, st, ae) != 0)
        die("state: " + ae.msg);

    for (size_t i = 1; i < backends.size(); ++i)
    {
        cs::runtime_state other;
        if (cs::read_runtime_state(*backends[i].fds, other, ae) != 0)
            die("state: " + ae.msg);
        if (!runtime_state_equal(st, other))
            die("state: backend states differ; refusing to sync");
    }

    std::vector<uint8_t> canon;
    cs::policy_summary sum;
    if (cs::build_policy_from_runtime(st, canon, sum, ae) != 0)
        die("state: " + ae.msg);

    std::string hash = cs::sha256_hex(canon);
    if (store.store_policy_blob(hash, canon, se) != 0) die("state: " + se.msg);

    std::vector<std::string> hist;
    if (store.read_history(hist, se) != 0) die("state: " + se.msg);
    store.history_push(hist, hash);
    if (store.write_history(hist, se) != 0) die("state: " + se.msg);

    cs::active_info ai;
    ai.sha256 = hash;
    ai.kind = sum.kind;
    ai.v = sum.v;
    ai.updated_at_ms = now_ms();
    ai.source = source;
    if (store.write_active(ai, se) != 0) die("state: " + se.msg);

    std::cout << "synced: " << hash << "\n";
}

} // namespace cs::runtime