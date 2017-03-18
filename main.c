#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include "shared_data.h"

#define PAGE_SIZE   4096


static void dump_user_request(struct shared_area *sa, struct hpvbd_user_request *req, int memfd)
{
    int i, nr_iovec = req->rw.nr_iovec > HPVBD_REQ_MAX_SEGMENTS ? HPVBD_REQ_MAX_SEGMENTS : req->rw.nr_iovec;
    ssize_t bytes;

    printf("tag = %d\n", req->rw.tag);
    printf("lba = %10llx, opcode = %d, buf_off = %10llx, len = %10llx\n",
            req->rw.slba, req->rw.opcode, req->rw.buf_off, req->rw.length);

    if (req->rw.opcode == hpvbd_cmd_write) {
        bytes = pwrite(memfd, sa->buffer + req->rw.buf_off, req->rw.length, req->rw.slba << 9);
        assert(bytes == req->rw.length);
    } else if (req->rw.opcode == hpvbd_cmd_read) {
        bytes = pread(memfd, sa->buffer + req->rw.buf_off, req->rw.length, req->rw.slba << 9);
        assert(bytes == req->rw.length);
    }

#if 0
    for (i = 0; i < nr_iovec; ++i) {
        unsigned long phys_addr = req->rw.iovec[i].phys_addr;
        unsigned long len = req->rw.iovec[i].len;

        printf("phys_addr = %10llx, len = %d\n", req->rw.iovec[i].phys_addr, req->rw.iovec[i].len);

        void *memaddr = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, memfd, phys_addr);
        if (memaddr == MAP_FAILED) {
            printf("failed to mmap /dev/mem\n");
            continue;
        }

        printf("mmap /dev/mem ok\n");
        munmap(memaddr, len);
    }
#endif
}

int main()
{
    int rc;
    const char *file = "/dev/hpvbd0q0";
    int fd = open(file, O_RDWR);
    assert(fd >= 0);

    struct hpvbd_ioctl_admin admin_cmd;
    admin_cmd.opcode = hpvbd_admin_queue_info;
    rc = ioctl(fd, HPVBD_IOCTL_ADMIN_CMD, &admin_cmd);
    assert(rc == 0);

    printf("sa_size = %10llx\n", admin_cmd.queue_info.sa_size);
    printf("disk_sectors = %10llx\n", admin_cmd.queue_info.disk_sectors);


    /*
    int memfd = open("/dev/mem", O_RDWR);
    assert(memfd >= 0);
    */
    
    int memfd = open("./vdisk.img", O_RDWR|O_CREAT|O_TRUNC);
    assert(memfd >= 0);

    ftruncate(memfd, admin_cmd.queue_info.disk_sectors << 9);

    void *addr = mmap(NULL, admin_cmd.queue_info.sa_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    assert(addr != MAP_FAILED);

    struct shared_area *sa = addr;
    printf("sa->sa_size = %lu\n", sa->sa_size);

    struct hpvbd_user_request req;
    struct hpvbd_ioctl_io    cpl;

    int epfd = epoll_create(1);
    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = fd;
    rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    assert(rc == 0);

    while (1) {
        epoll_wait(epfd, &ev, 1, -1);

again:
        rc = hpvbd_ring_buffer_dequeue(&sa->sq, &req, 0);
        if (rc != 0) {
            continue;
        }

        dump_user_request(sa, &req, memfd);
        cpl.tag = req.rw.tag;

        rc = ioctl(fd, HPVBD_IOCTL_IO_CMD, &cpl);
        assert(rc == 0);
        goto again;
    }

    return 0;
}
