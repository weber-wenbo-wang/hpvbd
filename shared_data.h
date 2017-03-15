#ifndef _SHARED_DATA_H
#define _SHARED_DATA_H
#ifndef __KERNEL__
#  include <string.h>
#endif

#include <linux/types.h>

typedef struct {
        long counter;
} null_atomic64_t;

static inline long null_atomic64_read(null_atomic64_t *v)
{
    return (*(volatile long*)&(v)->counter);
}

static inline void null_atomic64_set(null_atomic64_t *v, long i)
{
    v->counter = i;
}

typedef struct {
    null_atomic64_t head;
    null_atomic64_t tail;
    long    size;
    long    item_size;
    long    buf_off;
} null_ring_buffer;

typedef struct {
    int     tag;
} null_user_request;

struct shared_area {
    unsigned long   sa_size;
    null_ring_buffer sq;
    char buffer[0];
};

void null_ring_buffer_init(null_ring_buffer *rb, long size, long item_size, void *buffer)
{
    null_atomic64_set(&rb->head, 0);
    null_atomic64_set(&rb->tail, 0);
    rb->size = size;
    rb->item_size = item_size;
    rb->buf_off = buffer - (void *)rb;
}

static inline void *null_rb_item(null_ring_buffer *rb, long index)
{
    return (char *)rb + rb->buf_off + index * rb->item_size;
}

unsigned long null_ring_buffer_entries(null_ring_buffer *rb)
{
    long head = null_atomic64_read(&rb->head);
    long tail = null_atomic64_read(&rb->tail);

    return ((unsigned long)tail - (unsigned long)head) % (unsigned long)rb->size;
}

int null_ring_buffer_enqueue(null_ring_buffer *rb, void *item, long item_size)
{
    long head = null_atomic64_read(&rb->head);
    long tail = null_atomic64_read(&rb->tail);
    long next_tail = (tail + 1) % rb->size;

    if (next_tail == head)
        return -1;

    if (item_size == 0)
        item_size = rb->item_size;

    null_atomic64_set(&rb->tail, next_tail);
    memcpy(null_rb_item(rb, tail), item, item_size);
    return 0;
}

int null_ring_buffer_dequeue(null_ring_buffer *rb, void *item, long item_size)
{
    long head = null_atomic64_read(&rb->head);
    long tail = null_atomic64_read(&rb->tail);
    long next_head = (head + 1) % rb->size;

    if (head == tail)
        return -1;

    if (item_size == 0)
        item_size = rb->item_size;

    memcpy(item, null_rb_item(rb, head), item_size);
    null_atomic64_set(&rb->head, next_head);
    return 0;
}


struct null_user_io {
        __u8    opcode;
        __u32   tag;
};

#define NULL_IOCTL_IO_CMD   _IOWR('N', 0x43, struct null_user_io)

#endif
