#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum cindersentinel_counter_key
{
    CINDERSENTINEL_COUNTER_PASSED = 0,
    CINDERSENTINEL_COUNTER_DROPPED_TOTAL = 1,
    CINDERSENTINEL_COUNTER_DROPPED_ICMP = 2,
    CINDERSENTINEL_COUNTER_DROPPED_TCP_PORT = 3,
    CINDERSENTINEL_COUNTER_DROPPED_UDP_PORT = 4,
    CINDERSENTINEL_COUNTER_MAX = 5
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CINDERSENTINEL_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} cs_cnt SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u8);
} cs_blk_tcp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u8);
} cs_blk_udp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_icmp SEC(".maps");

static __always_inline void cindersentinel_increment_counter(enum cindersentinel_counter_key counter_key)
{
    __u32 key = (__u32)counter_key;
    __u64 *value = bpf_map_lookup_elem(&cs_cnt, &key);
    if (value)
    {
        (*value)++;
    }
}

static __always_inline bool cindersentinel_is_icmp_blocked()
{
    __u32 key = 0;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_icmp, &key);
    if (!value)
    {
        return false;
    }
    return (*value) != 0;
}

static __always_inline bool cindersentinel_is_tcp_port_blocked(__u16 destination_port_host_order)
{
    __u16 key = destination_port_host_order;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_tcp, &key);
    return value && (*value != 0);
}

static __always_inline bool cindersentinel_is_udp_port_blocked(__u16 destination_port_host_order)
{
    __u16 key = destination_port_host_order;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_udp, &key);
    return value && (*value != 0);
}

static __always_inline int cindersentinel_drop(enum cindersentinel_counter_key reason_key)
{
    cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_TOTAL);
    cindersentinel_increment_counter(reason_key);
    return TC_ACT_SHOT;
}

SEC("classifier")
int cindersentinel_classifier(struct __sk_buff *packet_context)
{
    void *data = (void *)(long)packet_context->data;
    void *data_end = (void *)(long)packet_context->data_end;

    struct ethhdr *ethernet_header = data;
    if ((void *)(ethernet_header + 1) > data_end)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    __u16 ether_type = bpf_ntohs(ethernet_header->h_proto);
    if (ether_type != ETH_P_IP)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = (void *)(ethernet_header + 1);
    if ((void *)(ip_header + 1) > data_end)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    if (ip_header->version != 4)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    __u32 ip_header_length = (__u32)ip_header->ihl * 4u;
    if (ip_header_length < sizeof(*ip_header))
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    if ((void *)ip_header + ip_header_length > data_end)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    __u16 fragment_offset = bpf_ntohs(ip_header->frag_off);
    if (fragment_offset & 0x1FFF)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }
    if (fragment_offset & 0x2000)
    {
        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    void *layer4 = (void *)ip_header + ip_header_length;

    if (ip_header->protocol == IPPROTO_ICMP)
    {
        if (cindersentinel_is_icmp_blocked())
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_ICMP);
        }

        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = layer4;
        if ((void *)(tcp_header + 1) > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
            return TC_ACT_OK;
        }

        __u16 destination_port = bpf_ntohs(tcp_header->dest);
        if (cindersentinel_is_tcp_port_blocked(destination_port))
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_TCP_PORT);
        }

        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_header = layer4;
        if ((void *)(udp_header + 1) > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
            return TC_ACT_OK;
        }

        __u16 destination_port = bpf_ntohs(udp_header->dest);
        if (cindersentinel_is_udp_port_blocked(destination_port))
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_UDP_PORT);
        }

        cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
        return TC_ACT_OK;
    }

    cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
