#ifndef CINDERSENTINEL_COMMON_H
#define CINDERSENTINEL_COMMON_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CINDERSENTINEL_VLAN_MAX_DEPTH 2

struct cindersentinel_vlan_hdr
{
    __be16 tci;
    __be16 encapsulated_proto;
};

static __always_inline bool cindersentinel_advance_vlan(void **cursor, void *data_end, __u16 *ether_type)
{
    struct cindersentinel_vlan_hdr *vh = *cursor;
    if ((void *)(vh + 1) > data_end)
    {
        return false;
    }

    *ether_type = bpf_ntohs(vh->encapsulated_proto);
    *cursor = (void *)(vh + 1);
    return true;
}

static __always_inline bool cindersentinel_parse_ethertype(struct ethhdr *ethernet_header,
                                                           void *data_end,
                                                           __u16 *out_ether_type,
                                                           void **out_network_header)
{
    __u16 ether_type = bpf_ntohs(ethernet_header->h_proto);
    void *cursor = (void *)(ethernet_header + 1);

#pragma unroll
    for (int i = 0; i < CINDERSENTINEL_VLAN_MAX_DEPTH; i++)
    {
        if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD)
        {
            if (!cindersentinel_advance_vlan(&cursor, data_end, &ether_type))
            {
                return false;
            }
        }
        else
        {
            break;
        }
    }

    *out_ether_type = ether_type;
    *out_network_header = cursor;
    return true;
}

enum cindersentinel_counter_key
{
    CINDERSENTINEL_COUNTER_PASSED = 0,
    CINDERSENTINEL_COUNTER_DROPPED_TOTAL = 1,
    CINDERSENTINEL_COUNTER_DROPPED_ICMP = 2,
    CINDERSENTINEL_COUNTER_DROPPED_TCP_PORT = 3,
    CINDERSENTINEL_COUNTER_DROPPED_UDP_PORT = 4,
    CINDERSENTINEL_COUNTER_DROPPED_IPV4_FRAG = 5,
    CINDERSENTINEL_COUNTER_DROPPED_IPV4_ENCAP = 6,
    CINDERSENTINEL_COUNTER_DROPPED_INVALID_L4 = 7,
    CINDERSENTINEL_COUNTER_DROPPED_INVALID_TCP_HEADER = 8,
    CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH = 9,
    CINDERSENTINEL_COUNTER_MAX = 10
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_tcp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_udp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_icmp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_ipv4_frag SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} cs_blk_ipv4_encap SEC(".maps");

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
    __u32 key = (__u32)destination_port_host_order;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_tcp, &key);
    return value && (*value != 0);
}

static __always_inline bool cindersentinel_is_udp_port_blocked(__u16 destination_port_host_order)
{
    __u32 key = (__u32)destination_port_host_order;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_udp, &key);
    return value && (*value != 0);
}

static __always_inline bool cindersentinel_ipv4_fragments_drop()
{
    __u32 key = 0;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_ipv4_frag, &key);
    if (!value)
    {
        return true;
    }
    return (*value) == 0;
}

static __always_inline bool cindersentinel_ipv4_encap_drop()
{
    __u32 key = 0;
    __u8 *value = bpf_map_lookup_elem(&cs_blk_ipv4_encap, &key);
    if (!value)
    {
        return false;
    }
    return (*value) == 0;
}

static __always_inline int cindersentinel_pass(int pass_action)
{
    cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_PASSED);
    return pass_action;
}

static __always_inline int cindersentinel_drop(enum cindersentinel_counter_key reason_key, int drop_action)
{
    cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_TOTAL);
    cindersentinel_increment_counter(reason_key);
    return drop_action;
}

static __always_inline int cindersentinel_process_ipv4(void *data, void *data_end, int pass_action, int drop_action)
{
    struct ethhdr *ethernet_header = data;
    if ((void *)(ethernet_header + 1) > data_end)
    {
        return cindersentinel_pass(pass_action);
    }

    __u16 ether_type = 0;
    void *network_header = (void *)0;
    if (!cindersentinel_parse_ethertype(ethernet_header, data_end, &ether_type, &network_header))
    {
        return cindersentinel_pass(pass_action);
    }

    if (ether_type != ETH_P_IP)
    {
        return cindersentinel_pass(pass_action);
    }

    struct iphdr *ip_header = network_header;
    if ((void *)(ip_header + 1) > data_end)
    {
        return cindersentinel_pass(pass_action);
    }

    if (ip_header->version != 4)
    {
        return cindersentinel_pass(pass_action);
    }

    __u32 ip_header_length = (__u32)ip_header->ihl * 4u;
    if (ip_header_length < sizeof(*ip_header))
    {
        return cindersentinel_pass(pass_action);
    }

    if ((void *)ip_header + ip_header_length > data_end)
    {
        return cindersentinel_pass(pass_action);
    }

    __u16 fragment_offset = bpf_ntohs(ip_header->frag_off);
    if ((fragment_offset & 0x1FFF) || (fragment_offset & 0x2000))
    {
        if (cindersentinel_ipv4_fragments_drop())
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_IPV4_FRAG, drop_action);
        }
        return cindersentinel_pass(pass_action);
    }

    void *layer4 = (void *)ip_header + ip_header_length;

    if (ip_header->protocol == IPPROTO_ICMP)
    {
        if (cindersentinel_is_icmp_blocked())
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_ICMP, drop_action);
        }

        return cindersentinel_pass(pass_action);
    }

    if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = layer4;
        if ((void *)(tcp_header + 1) > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_TCP_HEADER);
            return cindersentinel_pass(pass_action);
        }

        __u32 tcp_header_length = (__u32)tcp_header->doff * 4u;
        if (tcp_header_length < sizeof(*tcp_header))
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_TCP_HEADER);
            return cindersentinel_pass(pass_action);
        }

        if ((void *)tcp_header + tcp_header_length > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_TCP_HEADER);
            return cindersentinel_pass(pass_action);
        }

        __u16 destination_port = bpf_ntohs(tcp_header->dest);
        if (cindersentinel_is_tcp_port_blocked(destination_port))
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_TCP_PORT, drop_action);
        }

        return cindersentinel_pass(pass_action);
    }

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_header = layer4;
        if ((void *)(udp_header + 1) > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH);
            return cindersentinel_pass(pass_action);
        }

        __u16 udp_length = bpf_ntohs(udp_header->len);
        if (udp_length < sizeof(*udp_header))
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH);
            return cindersentinel_pass(pass_action);
        }

        __u32 ip_total_length = (__u32)bpf_ntohs(ip_header->tot_len);
        if (ip_total_length < ip_header_length + sizeof(*udp_header))
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH);
            return cindersentinel_pass(pass_action);
        }

        if (udp_length > ip_total_length - ip_header_length)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH);
            return cindersentinel_pass(pass_action);
        }

        if ((void *)udp_header + udp_length > data_end)
        {
            cindersentinel_increment_counter(CINDERSENTINEL_COUNTER_DROPPED_INVALID_UDP_LENGTH);
            return cindersentinel_pass(pass_action);
        }

        __u16 destination_port = bpf_ntohs(udp_header->dest);
        if (cindersentinel_is_udp_port_blocked(destination_port))
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_UDP_PORT, drop_action);
        }

        return cindersentinel_pass(pass_action);
    }

    if (ip_header->protocol == IPPROTO_IPIP || ip_header->protocol == IPPROTO_GRE ||
        (ip_header->protocol != IPPROTO_ICMP && ip_header->protocol != IPPROTO_TCP &&
         ip_header->protocol != IPPROTO_UDP))
    {
        if (cindersentinel_ipv4_encap_drop())
        {
            return cindersentinel_drop(CINDERSENTINEL_COUNTER_DROPPED_IPV4_ENCAP, drop_action);
        }
    }

    return cindersentinel_pass(pass_action);
}

#endif