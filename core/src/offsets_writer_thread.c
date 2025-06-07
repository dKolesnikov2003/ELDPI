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
        "timestamp_us INTEGER PRIMARY KEY,"
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
             "ON \"%s\"(timestamp_us);", ctx->name_pattern, ctx->name_pattern);
    sqlite3_exec(db, idx_sql, NULL, NULL, NULL);

    char insert_sql[512];
    snprintf(insert_sql, sizeof(insert_sql),
             "INSERT INTO \"%s\" "
             "(timestamp_us, file_offset, packet_len) "
             "VALUES (?, ?, ?);", ctx->name_pattern);
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &ins, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "prepare offsets INSERT: %s\n", sqlite3_errmsg(db));
        goto finish_db;
    }

    int       batch_cnt = 0;
    long long batch_ts  = 0;
    int       in_tx     = 0;

    for(;;) {
        OffsetItem *item = (OffsetItem *)queue_pop(ctx->offsets_queue);
        if (item == NULL) {                  
            break;
        }

        long long fofs = ftello(dump_fp);
        if (fofs < 0) fofs = 0; 
        fofs += 16;
        
        pcap_dump((u_char *)dumper, &item->packet->header,
                  item->packet->data);
        uint32_t plen = item->packet->header.caplen;

        if (!in_tx) {
            sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            in_tx    = 1;
            batch_ts = now_ms();
        }

        sqlite3_bind_int64(ins, 1, (sqlite3_int64)item->timestamp_us);
        sqlite3_bind_int64(ins, 2, (sqlite3_int64)fofs);
        sqlite3_bind_int  (ins, 3, plen);

        rc = sqlite3_step(ins);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "INSERT offsets: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_reset(ins);
        batch_cnt++;

        long long now = now_ms();
        if (batch_cnt >= BATCH_MAX ||
            (now - batch_ts) >= BATCH_MAX_MS)
        {
            if (in_tx) {
                sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
                in_tx = 0;
                batch_cnt = 0;
            }
            fflush(dump_fp);
        }

        free(item->packet);
        free(item);
    }
    
    if (in_tx)
        sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    fflush(dump_fp);

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