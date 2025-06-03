#ifndef OFFSETS_WRITER_THREAD_H
#define OFFSETS_WRITER_THREAD_H

#include <netinet/in.h>

typedef struct {
    uint64_t timestamp_ms;
    uint32_t packet_length;
    uint64_t pcap_file_offset;
} OffsetItem;


#endif // OFFSETS_WRITER_THREAD_H