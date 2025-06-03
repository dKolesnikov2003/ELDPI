#ifndef DPI_THREAD_H
#define DPI_THREAD_H

#include <pthread.h>

#include <ndpi/ndpi_api.h>

#include "queue.h"

#define FLOW_HASH_SIZE 8192

typedef struct {
    uint8_t ip_version; 
    union {
        struct { uint32_t src_ip, dst_ip; } v4;
        struct { uint64_t src_ip[2], dst_ip[2]; } v6;
    } ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} FlowKey;

typedef struct {
    struct ndpi_detection_module_struct *ndpi_struct;
    void *flow_table[FLOW_HASH_SIZE];
} NDPI_ThreadInfo;

typedef struct {
    pthread_t tid;
    int thread_number;
    GenericQueue *packet_queue;
    NDPI_ThreadInfo *ndpi_info;
    GenericQueue *metadata_queue;
    GenericQueue *offsets_queue;
} DPIThreadContext;

void init_dpi_thread(int thread_number, DPIThreadContext *dpi_ctx, GenericQueue *packet_queue, GenericQueue *metadata_queue, GenericQueue *offsets_queue);
void *dpi_thread(void *arg);
void destroy_dpi_context(DPIThreadContext *dpi_ctx);

#endif // DPI_THREAD_H