#include "eldpi_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <pcap.h>

#include "common.h"
#include "cap_thread.h"
#include "queue.h"


CapThreadContext *start_analysis(CapArgs *args) {
    if (!args) {
        fprintf(stderr, "Неверные параметры захвата\n");
        return NULL;
    }
    GenericQueue *packet_queues = calloc(THREAD_COUNT, sizeof(GenericQueue));
    if (!packet_queues) {
        perror("Ошибка выделения памяти для очередей");
        return NULL;
    }
    for(int i = 0; i < THREAD_COUNT; i++) {
        queue_init(&packet_queues[i], 1024);
    }
    pthread_t cap_thread_tid;
    CapThreadContext *ctx = cap_thread_init(cap_thread_tid, args, packet_queues);
    if (!ctx) {
        for (int i = 0; i < THREAD_COUNT; i++)
            queue_destroy(&packet_queues[i]);
        free(packet_queues);
        return NULL;
    }
    if(pthread_create(&cap_thread_tid, NULL, cap_thread, ctx) || !ctx) {
        perror("Ошибка при создании потока захвата");
        for(int i = 0; i < THREAD_COUNT; i++) {
            queue_destroy(&packet_queues[i]);
        }
        free(packet_queues);        
        free(ctx);
        return NULL;
    }
    ctx->tid = cap_thread_tid;

    

    return ctx;
}

void stop_analysis(CapThreadContext *ctx) {
    if (!ctx || !ctx->tid || !ctx->pcap_handle) {
        fprintf(stderr, "Нечего останавливать\n");
        return;
    }
    fprintf(stdout, "Остановка анализа...\n");
    pcap_breakloop(ctx->pcap_handle);
    pthread_join(ctx->tid, NULL);

    fprintf(stdout, "Захват остановлен\n");
}

void destroy_analysis_ctx(CapThreadContext *ctx) {
    if (!ctx) return;
    free(ctx->queues);
    free(ctx);
}