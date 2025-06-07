#ifndef OFFSETS_WRITER_THREAD_H
#define OFFSETS_WRITER_THREAD_H

#include <netinet/in.h>
#include <pthread.h>
#include "queue.h"

struct PacketItem;
struct CapThreadContext;

typedef struct {
    uint64_t timestamp_us;
    struct PacketItem *packet;
} OffsetItem;

typedef struct {
    pthread_t       tid;
    GenericQueue   *offsets_queue;
    const char     *name_pattern; 
    struct CapThreadContext *cap_ctx;

    char            pcap_path[128];
    char            db_path[128];
} OffsetsWriterThreadContext;

int offsets_writer_thread_init(OffsetsWriterThreadContext *offsets_writer_ctx, GenericQueue *offsets_queue, const char *name_pattern, struct CapThreadContext *cap_ctx);
void *offsets_writer_thread(void *arg);
void destroy_offsets_writer_context(OffsetsWriterThreadContext *offsets_writer_ctx);

#endif // OFFSETS_WRITER_THREAD_H