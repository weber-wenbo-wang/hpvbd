#ifndef _SHARED_DATA_H
#define _SHARED_DATA_H
#ifndef __KERNEL__
#  include <string.h>
#endif

#include <linux/types.h>

#ifndef __KERNEL__
#define barrier() __asm__ __volatile__("": : :"memory")
#define smp_mb()    asm volatile("mfence" : : : "memory")
#define smp_rmb()   barrier()
#define smp_wmb()   barrier()
#endif

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


enum null_opcode {
    null_cmd_invalid = 0x00,
    null_cmd_write,
    null_cmd_read,
};

#define NULL_REQ_MAX_SEGMENTS   8
#define NULL_REQ_MAX_SECTORS    128

struct null_iovec {
    unsigned long   phys_addr;
    unsigned int    len;
};

/* request to userspace server */
struct null_user_request {
    union {
        struct {
            enum null_opcode    opcode;
            int                 tag;
            unsigned long       slba;
            unsigned long       length;
            unsigned long       buf_off;
            int                 nr_iovec;
            struct null_iovec   iovec[NULL_REQ_MAX_SEGMENTS];
        } rw;
    };
};

struct shared_area {
    unsigned long   sa_size;
    null_ring_buffer sq;
    long            databuf_off;
    char buffer[0];
};

unsigned long null_ring_buffer_size_needed(long size, long item_size)
{
    return (size + 1) * item_size;
}

void null_ring_buffer_init(null_ring_buffer *rb, long size, long item_size, void *buffer)
{
    null_atomic64_set(&rb->head, 0);
    null_atomic64_set(&rb->tail, 0);
    rb->size = size + 1;
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

    memcpy(null_rb_item(rb, tail), item, item_size);
    smp_wmb();      // write data before updating rb->tail
    null_atomic64_set(&rb->tail, next_tail);
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

    smp_rmb();      // read rb->tail before read data
    memcpy(item, null_rb_item(rb, head), item_size);
    smp_mb();       // update rb->head after read data
    null_atomic64_set(&rb->head, next_head);
    return 0;
}


struct null_user_io {
    __u32   tag;
};


enum null_user_admin_opcode {
    null_uao_queue_info = 0x01,
};

struct null_user_admin {
    __u8    opcode;
    union {
        struct {
            unsigned long sa_size;
        } queue_info;
    };
};

#define NULL_IOCTL_ADMIN_CMD _IOWR('N', 0x42, struct null_user_admin)
#define NULL_IOCTL_IO_CMD   _IOWR('N', 0x43, struct null_user_io)

#endif
