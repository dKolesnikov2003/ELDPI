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

typedef struct {
    struct pcap_pkthdr header; 
    unsigned char data[];
} PacketItem;

CapThreadContext *cap_thread_init(pthread_t tid, CapArgs *args, GenericQueue *queues);
void *cap_thread(void *args);

#endif // CAP_THREAD_H  