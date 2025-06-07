#ifndef CAP_THREAD_H
#define CAP_THREAD_H

#include <pcap.h>

#include "queue.h"
#include "eldpi_api.h"

typedef struct CapThreadContext {
    pthread_t tid;
    pcap_t *pcap_handle;
    CapArgs *cap_args;
    GenericQueue *queues;
} CapThreadContext;

typedef struct PacketItem {
    struct pcap_pkthdr header; 
    unsigned char data[];
} PacketItem;

int cap_thread_init(CapThreadContext *cap_ctx, CapArgs *args, GenericQueue *queues);
void *cap_thread(void *args);
void destroy_cap_context(CapThreadContext *opts);

#endif // CAP_THREAD_H  