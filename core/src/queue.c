#include "queue.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>


void queue_init(GenericQueue *q, int capacity);
void increase_producer_count(GenericQueue *q);
void decrease_producer_count(GenericQueue *q);
void queue_destroy(GenericQueue *q);
int queue_push(GenericQueue *q, void *item);
void *queue_pop(GenericQueue *q);
int is_empty(GenericQueue *q);
int is_full(GenericQueue *q);

void queue_init(GenericQueue *q, int capacity) {
    q->items = calloc(capacity, sizeof(*q->items));
    if (!q->items) {
        perror("Ошибка выделения памяти для очереди");
        exit(EXIT_FAILURE);
    }
    q->capacity = capacity;
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    q->producer_count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_nonempty, NULL);
    pthread_cond_init(&q->cond_nonfull, NULL);
}

void increase_producer_count(GenericQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->producer_count++;
    pthread_mutex_unlock(&q->mutex);
}

void decrease_producer_count(GenericQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->producer_count--;
    if (q->producer_count == 0) {
        pthread_cond_broadcast(&q->cond_nonempty);
    }
    pthread_mutex_unlock(&q->mutex);
}

void queue_destroy(GenericQueue *q) {
    free(q->items);
    q->items = NULL;
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_nonempty);
    pthread_cond_destroy(&q->cond_nonfull);
}

int queue_push(GenericQueue *q, void *item) {
    pthread_mutex_lock(&q->mutex);
    while (is_full(q)) {
        pthread_cond_wait(&q->cond_nonfull, &q->mutex);
    }
    q->items[q->rear] = item;
    q->rear = (q->rear + 1) % q->capacity;
    q->count++;
    pthread_cond_broadcast(&q->cond_nonempty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

void *queue_pop(GenericQueue *q) {
    pthread_mutex_lock(&q->mutex);
    while (is_empty(q) && q->producer_count > 0) {
        pthread_cond_wait(&q->cond_nonempty, &q->mutex);
    }
    if (is_empty(q)) {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }
    void *item = q->items[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->count--;
    pthread_cond_broadcast(&q->cond_nonfull);
    pthread_mutex_unlock(&q->mutex);
    return item;
}

int is_empty(GenericQueue *q) {
    return q->count == 0;
}

int is_full(GenericQueue *q) {
    return q->count == q->capacity;
}
