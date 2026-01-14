#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum drop_reason
{
    DROP_NONE = 0,
    DROP_UNKNOWN = 1,
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &key);
    if (v) (*v)++;
}

SEC("xdp")
int gatekeeper_xdp(struct xdp_md *ctx) { count(DROP_NONE); return XDP_PASS; }

char _license[] SEC("license") = "GPL";
