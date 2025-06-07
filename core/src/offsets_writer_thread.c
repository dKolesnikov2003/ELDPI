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

    int  dlt     = pcap_datalink(ctx->cap_ctx->pcap_handle);
    int  snaplen = pcap_snapshot(ctx->cap_ctx->pcap_handle);

    pcap_t *dead = pcap_open_dead(dlt, snaplen);
    if (!dead) {
        fprintf(stderr, "pcap_open_dead failed\n");
        goto finish;
    }
    pcap_dumper_t *dumper = pcap_dump_open(dead, ctx->pcap_path);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open: %s\n", pcap_geterr(dead));
        goto finish_dead;
    }
    FILE *dump_fp = pcap_dump_file(dumper); 

    sqlite3 *db = NULL;
    sqlite3_stmt *ins = NULL;
    int rc = sqlite3_open_v2(ctx->db_path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
        goto finish_dumper;
    }

    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    char create_sql[1024];
    snprintf(create_sql, sizeof(create_sql),
        "CREATE TABLE IF NOT EXISTS \"%s\" ("
        "timestamp_ms INTEGER PRIMARY KEY,"
        "file_offset  INTEGER NOT NULL,"
        "packet_len   INTEGER NOT NULL);",
        ctx->name_pattern);

    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "CREATE offsets table: %s\n", sqlite3_errmsg(db));
        goto finish_db;
    }

    char idx_sql[1024];
    snprintf(idx_sql, sizeof(idx_sql),
             "CREATE INDEX IF NOT EXISTS \"%s_offsets_ts_idx\" "
             "ON \"%s_offsets\"(timestamp_ms);", ctx->name_pattern, ctx->name_pattern);
    sqlite3_exec(db, idx_sql, NULL, NULL, NULL);

    for(;;) {
        OffsetItem *item = (OffsetItem *)queue_pop(ctx->offsets_queue);
        if (item == NULL) {                  
            break;
        }

        printf("offsets_writer_thread: Получен элемент с timestamp %lu\n", item->timestamp_ms);
        printf("offsets_writer_thread: Получен пакет с длиной %d\n\n", item->packet->header.caplen);

        free(item->packet);
        free(item);
    }

finish_db:
    if (ins) sqlite3_finalize(ins);
    if (db)  sqlite3_close(db);
finish_dumper:
    if (dumper) pcap_dump_close(dumper);
finish_dead:
    if (dead)   pcap_close(dead);
finish:

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