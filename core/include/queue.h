#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

typedef struct {
    void **items;
    int capacity;
    int front;
    int rear;
    int count;
    int producer_count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
} GenericQueue;

void queue_init(GenericQueue *q, int capacity);
void increase_producer_count(GenericQueue *q);
void decrease_producer_count(GenericQueue *q);
void queue_destroy(GenericQueue *q);
int queue_push(GenericQueue *q, void *item);
void *queue_pop(GenericQueue *q);
int is_empty(GenericQueue *q);
int is_full(GenericQueue *q);


#endif // QUEUE_H