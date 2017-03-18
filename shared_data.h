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

#define HPVBD_REQ_MAX_SEGMENTS   8

typedef struct {
        long counter;
} hpvbd_atomic64_t;

static inline long hpvbd_atomic64_read(hpvbd_atomic64_t *v)
{
    return (*(volatile long*)&(v)->counter);
}

static inline void hpvbd_atomic64_set(hpvbd_atomic64_t *v, long i)
{
    v->counter = i;
}

typedef struct {
    hpvbd_atomic64_t head;
    hpvbd_atomic64_t tail;
    long    size;
    long    item_size;
    long    buf_off;
} hpvbd_ring_buffer;


enum hpvbd_opcode {
    hpvbd_cmd_invalid = 0x00,
    hpvbd_cmd_write,
    hpvbd_cmd_read,
};

struct hpvbd_iovec {
    unsigned long   phys_addr;
    unsigned int    len;
};

/* request to userspace server */
struct hpvbd_user_request {
    union {
        struct {
            enum hpvbd_opcode    opcode;
            int                 tag;
            unsigned long       slba;
            unsigned long       length;
            unsigned long       buf_off;
            int                 nr_iovec;
            struct hpvbd_iovec   iovec[HPVBD_REQ_MAX_SEGMENTS];
        } rw;
    };
};

struct shared_area {
    unsigned long   sa_size;
    hpvbd_ring_buffer sq;
    long            databuf_off;
    char buffer[0];
};

unsigned long hpvbd_ring_buffer_size_needed(long size, long item_size)
{
    return (size + 1) * item_size;
}

void hpvbd_ring_buffer_init(hpvbd_ring_buffer *rb, long size, long item_size, void *buffer)
{
    hpvbd_atomic64_set(&rb->head, 0);
    hpvbd_atomic64_set(&rb->tail, 0);
    rb->size = size + 1;
    rb->item_size = item_size;
    rb->buf_off = buffer - (void *)rb;
}

static inline void *hpvbd_rb_item(hpvbd_ring_buffer *rb, long index)
{
    return (char *)rb + rb->buf_off + index * rb->item_size;
}

unsigned long hpvbd_ring_buffer_entries(hpvbd_ring_buffer *rb)
{
    long head = hpvbd_atomic64_read(&rb->head);
    long tail = hpvbd_atomic64_read(&rb->tail);

    return ((unsigned long)tail - (unsigned long)head) % (unsigned long)rb->size;
}

int hpvbd_ring_buffer_enqueue(hpvbd_ring_buffer *rb, void *item, long item_size)
{
    long head = hpvbd_atomic64_read(&rb->head);
    long tail = hpvbd_atomic64_read(&rb->tail);
    long next_tail = (tail + 1) % rb->size;

    if (next_tail == head)
        return -1;

    if (item_size == 0)
        item_size = rb->item_size;

    memcpy(hpvbd_rb_item(rb, tail), item, item_size);
    smp_wmb();      // write data before updating rb->tail
    hpvbd_atomic64_set(&rb->tail, next_tail);
    return 0;
}

int hpvbd_ring_buffer_dequeue(hpvbd_ring_buffer *rb, void *item, long item_size)
{
    long head = hpvbd_atomic64_read(&rb->head);
    long tail = hpvbd_atomic64_read(&rb->tail);
    long next_head = (head + 1) % rb->size;

    if (head == tail)
        return -1;

    if (item_size == 0)
        item_size = rb->item_size;

    smp_rmb();      // read rb->tail before read data
    memcpy(item, hpvbd_rb_item(rb, head), item_size);
    smp_mb();       // update rb->head after read data
    hpvbd_atomic64_set(&rb->head, next_head);
    return 0;
}


struct hpvbd_ioctl_io {
    __u32   tag;
};


enum hpvbd_ioctl_admin_opcode {
    hpvbd_admin_queue_info = 0x01,
};

struct hpvbd_ioctl_admin {
    __u8    opcode;
    union {
        struct {
            unsigned long sa_size;
            unsigned long disk_sectors;     // 512 bytes per sector
        } queue_info;
    };
};

#define HPVBD_IOCTL_ADMIN_CMD _IOWR('N', 0x42, struct hpvbd_ioctl_admin)
#define HPVBD_IOCTL_IO_CMD   _IOWR('N', 0x43, struct hpvbd_ioctl_io)

#endif
