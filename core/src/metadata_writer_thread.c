#define _POSIX_C_SOURCE 199309L
#include "metadata_writer_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#include <sqlite3.h>

#include "common.h"
#include "queue.h"
#include "eldpi_api.h"
#include "utils.h"

int metadata_writer_thread_init(MetadataWriterThreadContext *ctx,
                                GenericQueue *metadata_queue,
                                const char *name_pattern)
{
    if (!ctx || !metadata_queue || !name_pattern) {
        fprintf(stderr,
                "Неверные параметры для инициализации потока записи метаданных\n");
        return 1;
    }

    char *data_dir = get_data_dir();
    if (!data_dir || ensure_dir_exists(data_dir) != 0) {
        perror("Не удалось подготовить каталог для БД");
        return 1;
    }

    snprintf(ctx->db_path, sizeof(ctx->db_path), "%s/metadata.db", data_dir);

    ctx->tid             = 0;
    ctx->metadata_queue  = metadata_queue;
    ctx->name_pattern    = name_pattern;
    return 0;
}

void *metadata_writer_thread(void *arg) {
    MetadataWriterThreadContext *ctx = (MetadataWriterThreadContext *)arg;
    sqlite3      *db  = NULL;
    sqlite3_stmt *ins = NULL;
    int           rc;

    rc = sqlite3_open_v2(ctx->db_path, &db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
        goto finish;
    }

    char create_sql[512];
    snprintf(create_sql, sizeof(create_sql),
             "CREATE TABLE IF NOT EXISTS \"%s\" ("
             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
             "timestamp_ms  INTEGER NOT NULL,"
             "session_id    INTEGER NOT NULL,"
             "ip_version    INTEGER NOT NULL,"
             "ip_src        TEXT    NOT NULL,"
             "ip_dst        TEXT    NOT NULL,"
             "src_port      INTEGER NOT NULL,"
             "dst_port      INTEGER NOT NULL,"
             "protocol_name TEXT    NOT NULL);",
             ctx->name_pattern);

    rc = sqlite3_exec(db, create_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_exec(CREATE TABLE): %s\n", sqlite3_errmsg(db));
        goto finish;
    }

    char insert_sql[256];
    snprintf(insert_sql, sizeof(insert_sql),
             "INSERT INTO \"%s\" (timestamp_ms, session_id, ip_version,"
             "ip_src, ip_dst, src_port, dst_port, protocol_name)"
             "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
             ctx->name_pattern);
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &ins, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_prepare: %s\n", sqlite3_errmsg(db));
        goto finish;
    }

    int         batch_cnt = 0;
    long long   batch_ts  = 0;
    int         in_tx     = 0;

    for (;;) {
        MetadataItem *item = (MetadataItem *)queue_pop(ctx->metadata_queue);

        if (item == NULL) {                  
            break;
        }

        if (!in_tx) {
            rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "BEGIN: %s\n", sqlite3_errmsg(db));
                /* не выходим, продолжаем без транзакции */
            } else {
                in_tx    = 1;
                batch_ts = now_ms();
            }
        }

        sqlite3_bind_int64(ins, 1, (sqlite3_int64)item->timestamp_ms);
        sqlite3_bind_int64(ins, 2, (sqlite3_int64)item->session_id);
        sqlite3_bind_int  (ins, 3, item->ip_version);

        char ip_src_buf[INET6_ADDRSTRLEN] = {0};
        char ip_dst_buf[INET6_ADDRSTRLEN] = {0};

        if (item->ip_version == 4) {
            inet_ntop(AF_INET,  &item->ip_src.v4, ip_src_buf, sizeof(ip_src_buf));
            inet_ntop(AF_INET,  &item->ip_dst.v4, ip_dst_buf, sizeof(ip_dst_buf));
        } else {
            inet_ntop(AF_INET6, &item->ip_src.v6, ip_src_buf, sizeof(ip_src_buf));
            inet_ntop(AF_INET6, &item->ip_dst.v6, ip_dst_buf, sizeof(ip_dst_buf));
        }

        sqlite3_bind_text(ins, 4, ip_src_buf, -1, SQLITE_STATIC);
        sqlite3_bind_text(ins, 5, ip_dst_buf, -1, SQLITE_STATIC);
        sqlite3_bind_int (ins, 6, ntohs(item->src_port));
        sqlite3_bind_int (ins, 7, ntohs(item->dst_port));
        sqlite3_bind_text(ins, 8, item->protocol_name, -1, SQLITE_STATIC);

        rc = sqlite3_step(ins);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "INSERT: %s\n", sqlite3_errmsg(db));
        }
        sqlite3_reset(ins);
        batch_cnt++;

        long long now = now_ms();
        if (batch_cnt >= METADATA_BATCH_MAX ||
            (now - batch_ts) >= METADATA_BATCH_MAX_MS)
        {
            if (in_tx) {
                sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
                in_tx      = 0;
                batch_cnt  = 0;
            }
        }

        free(item);
    }

    if (in_tx)
        sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

finish:
    if (ins) sqlite3_finalize(ins);
    if (db)  sqlite3_close(db);

    printf("Сохранение метаданных анализа завершено успешно\n");
    pthread_exit(NULL);
}

void destroy_metadata_writer_context(MetadataWriterThreadContext *metadata_writer_ctx) {
    if (metadata_writer_ctx != NULL) {
        if (metadata_writer_ctx->metadata_queue != NULL) {
            queue_destroy(metadata_writer_ctx->metadata_queue);
            free(metadata_writer_ctx->metadata_queue);
            metadata_writer_ctx->metadata_queue = NULL;
        }                    
            
    }
}
