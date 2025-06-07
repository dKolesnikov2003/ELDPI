#include "eldpi_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <libgen.h>

#include <pcap.h>

#include "common.h"
#include "cap_thread.h"
#include "queue.h"
#include "dpi_thread.h"
#include "utils.h"



static void set_name_pattern(Contexts *ctx) {
    time_t now = time(NULL);
    struct tm tm = *localtime(&now);
    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d_%H-%M-%S", &tm);
    char source_buf[128];
    strncpy(source_buf, ctx->cap_ctx->cap_args->source_name, sizeof(source_buf) - 1);
    source_buf[sizeof(source_buf) - 1] = '\0';
    char *base_name = basename(source_buf);
    for (char *p = base_name; *p; ++p) {
        if (*p == '.') {
            *p = '-';
        }
    }
    snprintf(name_pattern, sizeof(name_pattern),
            "%c_%s_%s",
            (ctx->cap_ctx->cap_args->source_type == CAP_SRC_FILE ? 'f' : 'i'),
            base_name, datebuf);
}

Contexts *start_analysis(CapArgs *args) {
    if (!args) {
        fprintf(stderr, "Неверные параметры захвата\n");
        return NULL;
    }

    Contexts *ctx = calloc(1, sizeof(Contexts));
    if (!ctx) {
        perror("Ошибка выделения памяти");
        return NULL;
    }


    // Поток захвата пакетов
    GenericQueue *packet_queues = calloc(THREAD_COUNT, sizeof(GenericQueue));
    if (!packet_queues) {
        perror("Ошибка выделения памяти для очередей");
        return NULL;
    }
    for(int i = 0; i < THREAD_COUNT; i++) {
        queue_init(&packet_queues[i], 1024);
    }
    CapThreadContext *cap_ctx = calloc(1, sizeof(CapThreadContext));
    if (!cap_ctx) {
        perror("Ошибка выделения памяти для контекста захвата");
        return NULL;
    }
    if(cap_thread_init(cap_ctx, args, packet_queues) != 0) {
        fprintf(stderr, "Ошибка инициализации потока захвата\n");
        return NULL;
    }  
    if(pthread_create(&cap_ctx->tid, NULL, cap_thread, cap_ctx) || !cap_ctx) {
        perror("Ошибка при создании потока захвата");
        return NULL;
    }


    // Потоки DPI
    GenericQueue *metadata_queue = calloc(1, sizeof(GenericQueue));
    GenericQueue *offsets_queue  = calloc(1, sizeof(GenericQueue));
    if (!metadata_queue || !offsets_queue) {
        perror("Ошибка выделения памяти для очередей метаданных или смещений");       
        return NULL;
    }
    queue_init(metadata_queue, 1024 * THREAD_COUNT);
    queue_init(offsets_queue, 1024 * THREAD_COUNT);
    DPIThreadContext *dpi_threads = calloc(THREAD_COUNT, sizeof(DPIThreadContext));
    if (!dpi_threads) {
        perror("Ошибка выделения памяти для потоков DPI");
        return NULL;
    }

    for(int i = 0; i < THREAD_COUNT; i++) {
        if (dpi_thread_init(i, &dpi_threads[i], &packet_queues[i], metadata_queue, offsets_queue) != 0) {
            fprintf(stderr, "Ошибка инициализации потока DPI №%d\n", i);
            return NULL;
        }
        if (pthread_create(&dpi_threads[i].tid, NULL, dpi_thread, &dpi_threads[i])) {
            perror("Ошибка при создании потока DPI");
            return NULL;
        }
    }
    ctx->cap_ctx = cap_ctx;
    ctx->dpi_threads = dpi_threads;


    // Потоки сохранения метаданных и "сырых" пакетов
    set_name_pattern(ctx);
    MetadataWriterThreadContext *metadata_writer_ctx = calloc(1, sizeof(MetadataWriterThreadContext));
    if (!metadata_writer_ctx) {
        perror("Ошибка выделения памяти для потока записи метаданных");
        return NULL;
    }
    OffsetsWriterThreadContext *offsets_writer_ctx = calloc(1, sizeof(OffsetsWriterThreadContext));
    if (!offsets_writer_ctx) {
        perror("Ошибка выделения памяти для потока записи в файл");
        return NULL;
    }
    if (metadata_writer_thread_init(metadata_writer_ctx, metadata_queue, name_pattern) != 0) {
        fprintf(stderr, "Ошибка инициализации потока записи метаданных\n");
        return NULL;
    }
    if( offsets_writer_thread_init(offsets_writer_ctx, offsets_queue, name_pattern, cap_ctx) != 0) {
        fprintf(stderr, "Ошибка инициализации потока записи в файл\n");
        return NULL;
    }
    if(pthread_create(&metadata_writer_ctx->tid, NULL, metadata_writer_thread, metadata_writer_ctx)){
        perror("Ошибка при создании потока записи метаданных");
        return NULL;
    }
    if(pthread_create(&offsets_writer_ctx->tid, NULL, offsets_writer_thread, offsets_writer_ctx)){
        perror("Ошибка при создании потока записи в файл");
        return NULL;
    }
    ctx->metadata_writer_ctx = metadata_writer_ctx;
    ctx->offsets_writer_ctx = offsets_writer_ctx;

    return ctx;
}

void terminate_analysis(Contexts *ctx) {
    pthread_join(ctx->cap_ctx->tid, NULL);

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(ctx->dpi_threads[i].tid, NULL);
        destroy_dpi_context(&ctx->dpi_threads[i]);
    }
    free(ctx->dpi_threads[0].packet_queue);
    for (int i = 0; i < THREAD_COUNT; i++) {
        ctx->dpi_threads[i].packet_queue = NULL;
    }
    if (ctx->dpi_threads != NULL){
        free(ctx->dpi_threads);
        ctx->dpi_threads = NULL;
    }
    
    pthread_join(ctx->metadata_writer_ctx->tid, NULL);
    destroy_metadata_writer_context(ctx->metadata_writer_ctx);
    if (ctx->metadata_writer_ctx != NULL) {
        free(ctx->metadata_writer_ctx);
        ctx->metadata_writer_ctx = NULL;
    }
    
    pthread_join(ctx->offsets_writer_ctx->tid, NULL);
    destroy_offsets_writer_context(ctx->offsets_writer_ctx);
    if (ctx->offsets_writer_ctx != NULL) {
        free(ctx->offsets_writer_ctx);
        ctx->offsets_writer_ctx = NULL;
    }

    destroy_cap_context(ctx->cap_ctx);
    if (ctx->cap_ctx != NULL) {
        free(ctx->cap_ctx);
        ctx->cap_ctx = NULL;
    }
    
    
    fprintf(stdout, "Анализ завершён успешно\n");
}


void wait_analysis(Contexts *ctx) {
    if (!ctx || !ctx->cap_ctx->tid || !ctx->cap_ctx->pcap_handle) {
        fprintf(stderr, "Неверный контекст анализа\n");
        return;
    }
    terminate_analysis(ctx);
}

void stop_analysis(Contexts *ctx) {
    if (!ctx || !ctx->cap_ctx->tid || !ctx->cap_ctx->pcap_handle) {
        fprintf(stderr, "Неверный контекст анализа\n");
        return;
    }
    fprintf(stdout, "Остановка анализа...\n");
    pcap_breakloop(ctx->cap_ctx->pcap_handle);
    terminate_analysis(ctx);
}

char* get_data_dir() {
    return DATA_DIR;
} 

void destroy_analysis_context(Contexts *ctx) {
    if (!ctx) return;
    free(ctx);
}