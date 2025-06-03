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

#endif // METADATA_WRITER_THREAD_H