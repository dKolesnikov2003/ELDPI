#include "matadata_writer_thread.h"

#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "queue.h"


int init_metadata_writer_thread(MetadataWriterThreadContext *metadata_writer_ctx, GenericQueue *metadata_queue) {
    if (!metadata_writer_ctx || !metadata_queue) {
        fprintf(stderr, "Неверные параметры для инициализации потока записи метаданных пакетов\n");
        return 1;
    }

    metadata_writer_ctx->tid = 0;
    metadata_writer_ctx->metadata_queue = metadata_queue;

    if (pthread_create(&metadata_writer_ctx->tid, NULL, metadata_writer_thread, metadata_writer_ctx) != 0) {
        perror("Ошибка при создании потока записи метаданных");
        return 1;
    }

    return 0;
}

void *metadata_writer_thread(void *arg) {
    MetadataWriterThreadContext *metadata_writer_ctx = (MetadataWriterThreadContext *)arg;

    for (;;) {
        MetadataItem *item = (MetadataItem *)queue_pop(metadata_writer_ctx->metadata_queue);
        if (item == NULL) {
            break;
        }

        printf("Metadata: %lu %u %d %s:%d -> %s:%d %s\n",
               item->timestamp_ms, item->session_id, item->ip_version,
               inet_ntoa(item->ip_src.v4), ntohs(item->src_port),
               inet_ntoa(item->ip_dst.v4), ntohs(item->dst_port),
               item->protocol_name);

        free(item);
    }
    queue_destroy(metadata_writer_ctx->metadata_queue);
    pthread_exit(NULL);
}

void destroy_metadata_writer_context(MetadataWriterThreadContext *metadata_writer_ctx) {
    if (metadata_writer_ctx != NULL) {
        queue_destroy(metadata_writer_ctx->metadata_queue);
        free(metadata_writer_ctx->metadata_queue);
        metadata_writer_ctx->metadata_queue = NULL;
        free(metadata_writer_ctx);
        metadata_writer_ctx = NULL;
    }
}
