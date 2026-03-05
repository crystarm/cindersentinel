#include "cindersentinel_common.h"
#include <linux/pkt_cls.h>

SEC("classifier")
int cindersentinel_classifier(struct __sk_buff *packet_context)
{
    void *data = (void *)(long)packet_context->data;
    void *data_end = (void *)(long)packet_context->data_end;

    return cindersentinel_process_ipv4(data, data_end, TC_ACT_OK, TC_ACT_SHOT);
}

char _license[] SEC("license") = "GPL";
