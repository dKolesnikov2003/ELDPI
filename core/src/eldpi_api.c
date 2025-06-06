#include "eldpi_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <pcap.h>

#include "common.h"
#include "cap_thread.h"
#include "queue.h"
#include "dpi_thread.h"


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
    CapThreadContext *cap_ctx = cap_thread_init(args, packet_queues);
    if (!cap_ctx) {
        return NULL;
    }
    pthread_t cap_thread_tid;
    if(pthread_create(&cap_thread_tid, NULL, cap_thread, cap_ctx) || !cap_ctx) {
        perror("Ошибка при создании потока захвата");
    return NULL;
    }
    cap_ctx->tid = cap_thread_tid;

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
        if (init_dpi_thread(i, &dpi_threads[i], &packet_queues[i], metadata_queue, offsets_queue) != 0) {
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

    MetadataWriterThreadContext *metadata_writer_ctx = calloc(1, sizeof(MetadataWriterThreadContext));
    if (!metadata_writer_ctx) {
        perror("Ошибка выделения памяти для потока записи метаданных");
        return NULL;
    }
    if (init_metadata_writer_thread(metadata_writer_ctx, metadata_queue) != 0) {
        fprintf(stderr, "Ошибка инициализации потока записи метаданных\n");
        free(metadata_writer_ctx);
        return NULL;
    }
    if(pthread_create(&metadata_writer_ctx->tid, NULL, metadata_writer_thread, metadata_writer_ctx)){
        perror("Ошибка при создании потока записи метаданных");
            return NULL;
    }
    ctx->metadata_writer_ctx = metadata_writer_ctx;



    return ctx;
}

void terminate_analysis(Contexts *ctx) {
    pthread_join(ctx->cap_ctx->tid, NULL);

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(ctx->dpi_threads[i].tid, NULL);
        destroy_dpi_context(&ctx->dpi_threads[i]);
    }
    free(ctx->dpi_threads);

    pthread_join(ctx->metadata_writer_ctx->tid, NULL);
    destroy_metadata_writer_context(ctx->metadata_writer_ctx);
    free(ctx->metadata_writer_ctx);
    ctx->metadata_writer_ctx = NULL;

    destroy_cap_context(ctx->cap_ctx);
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

void destroy_analysis_context(Contexts *ctx) {
    if (!ctx) return;
    free(ctx->cap_ctx->queues);
    free(ctx->cap_ctx);
    free(ctx);
}