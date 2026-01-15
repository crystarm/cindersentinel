#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

enum cindersentinel_counter_key
{
    CINDERSENTINEL_COUNTER_PASSED = 0,
    CINDERSENTINEL_COUNTER_DROPPED = 1,
    CINDERSENTINEL_COUNTER_MAX = 2
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CINDERSENTINEL_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} cindersentinel_counters SEC(".maps");

static __always_inline void cindersentinel_increment_counter(enum cindersentinel_counter_key counter_key)
{
    __u32 key = (__u32)counter_key;
    __u64 *value = bpf_map_lookup_elem(&cindersentinel_counters, &key);
    if (value) { (*value)++; }
}

SEC("classifier")
int cindersentinel_classifier(struct __sk_buff *packet_context)
{
    (void)packet_context;

    cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
