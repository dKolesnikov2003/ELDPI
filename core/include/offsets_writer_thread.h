#ifndef OFFSETS_WRITER_THREAD_H
#define OFFSETS_WRITER_THREAD_H

#include <netinet/in.h>
#include <pthread.h>
#include "queue.h"

struct PacketItem;

typedef struct {
    uint64_t timestamp_ms;
    struct PacketItem *packet;
} OffsetItem;

// typedef struct {
//     pthread_t       tid;
//     GenericQueue   *offset_queue;         /* очередь OffsetItem'ов      */
//     const char     *name_pattern;         /* базовое имя файла/таблицы  */
//     CapThreadContext *cap_ctx;            /* нужен datalink/snaplen     */

//     /* ↓ ресурсы, подготавливаемые в init ↓ */
//     char            pcap_path[PATH_MAX];  /* …/*.pcap                   */
//     char            db_path[PATH_MAX];    /* …/metadata.db              */
// } PacketWriterThreadContext;

#endif // OFFSETS_WRITER_THREAD_H