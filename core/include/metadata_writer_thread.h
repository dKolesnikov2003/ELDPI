#ifndef METADATA_WRITER_THREAD_H
#define METADATA_WRITER_THREAD_H

#include <netinet/in.h>

typedef struct {
    uint64_t timestamp_ms;
    uint32_t session_id;
    uint8_t ip_version;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip_src;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip_dst;
    uint16_t src_port;
    uint16_t dst_port;
    char protocol_name[64];
} MetadataItem;

typedef struct {
    pthread_t tid;
    GenericQueue *metadata_queue;
} MetadataWriterThreadContext;

int init_metadata_writer_thread(MetadataWriterThreadContext *metadata_writer_ctx, GenericQueue *metadata_queue);
void *metadata_writer_thread(void *arg);
void destroy_metadata_writer_context(MetadataWriterThreadContext *metadata_writer_ctx);

#endif // METADATA_WRITER_THREAD_H