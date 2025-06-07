#include "offsets_writer_thread.h"

#include "cap_thread.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#include <pcap/pcap.h>
#include <sqlite3.h>

#include "common.h"
#include "queue.h"
#include "eldpi_api.h"

int offsets_writer_thread_init(OffsetsWriterThreadContext *ctx,
                               GenericQueue *offsets_queue,
                               const char *name_pattern,
                               CapThreadContext *cap_ctx)
{
    if (!ctx || !offsets_queue || !name_pattern || !cap_ctx) {
        fprintf(stderr, "Неверные параметры для инициализации потока записи в файл\n");
        return 1;
    }

    char *data_dir = get_data_dir();
    if (!data_dir || ensure_dir_exists(data_dir) != 0) {
        perror("Не удалось подготовить каталог для БД");
        return 1;
    }

    snprintf(ctx->db_path, sizeof(ctx->db_path), "%s/offsets.db", data_dir);
    snprintf(ctx->pcap_path, sizeof(ctx->pcap_path),  "%s/%s.pcap", data_dir, name_pattern);

    ctx->tid             = 0;
    ctx->offsets_queue   = offsets_queue;
    ctx->name_pattern    = name_pattern;
    ctx->cap_ctx         = cap_ctx;
    return 0;
}

void *offsets_writer_thread(void *arg) {
    OffsetsWriterThreadContext *ctx = (OffsetsWriterThreadContext *) arg;


    for(;;) {
        OffsetItem *item = (OffsetItem *)queue_pop(ctx->offsets_queue);
        if (item == NULL) {                  
            break;
        }

        printf("offsets_writer_thread: Получен элемент с timestamp %lu\n", item->timestamp_ms);

        // free(item->packet);
        // free(item);
    }
    printf("Сохранение пакетов завершено успешно\n");
    pthread_exit(NULL);
}

void destroy_offsets_writer_context(OffsetsWriterThreadContext *offsets_writer_ctx) {
    if (offsets_writer_ctx != NULL) {
        if (offsets_writer_ctx->offsets_queue != NULL) {
            queue_destroy(offsets_writer_ctx->offsets_queue);
            free(offsets_writer_ctx->offsets_queue);
            offsets_writer_ctx->offsets_queue = NULL;
        }
    }
}