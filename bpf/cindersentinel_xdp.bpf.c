#include "cindersentinel_common.h"


SEC("xdp")
int cindersentinel_xdp(struct xdp_md *packet_context)
{
    void *data = (void *)(long)packet_context->data;
    void *data_end = (void *)(long)packet_context->data_end;

    return cindersentinel_process_ipv4(data, data_end, XDP_PASS, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
