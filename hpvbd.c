/*
 * High Performance Virtual Block Device driver
 * Revised from null_blk.c
 *
 * TODO:
 * 1. Add an inflight io list, so io can be resubmitted when userspace
 *    server restarts.
 * 2. Timeout handling.
 * 3. Zero copy by revising /dev/mem or a new driver.
 * 4. sysfs/configfs/ioctl to dynamically create/destroy/modify vdisks.
 */
#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>

#include "shared_data.h"

#define HPVBD_REQ_MAX_SECTORS    128
#define HPVBD_MINORS     (1U << MINORBITS)

#define HPVBD_MK_MINOR(hpvbd_index, queue_index) \
    ((hpvbd_index) << 8 | (queue_index))

#define HPVBD_BLK_INDEX(minor)   \
    ((minor) >> 8)
#define HPVBD_QUEUE_INDEX(minor) \
    ((minor) & 0xff)

#define hpvbd_printk(level, dev, fmt, arg...) \
    do {    \
        printk(level "hpvbd%d: " fmt, (dev)->index, ## arg); \
    } while (0)

#define hpvbd_info(dev, fmt, arg...)            \
    do {                                \
        if (true) \
            hpvbd_printk(KERN_INFO, dev, fmt , ## arg);     \
    } while (0)

#define hpvbd_dbg(dev, fmt, arg...)            \
    do {                                \
        if (false) \
            hpvbd_printk(KERN_DEBUG, dev, fmt , ## arg);     \
    } while (0)

static struct class *hpvbd_class;

static int hpvbd_char_major;
module_param(hpvbd_char_major, int, 0);

struct hpvbd;

struct hpvbd_cmd {
	struct list_head list;
	struct llist_node ll_list;
	struct call_single_data csd;
	struct request *rq;
	struct bio *bio;
	unsigned int tag;
	struct hpvbd_queue *nq;
    struct hpvbd_user_request cmd;
};

struct hpvbd_queue {
	unsigned long *tag_map;
	wait_queue_head_t wait;
	unsigned int queue_depth;

	struct hpvbd_cmd *cmds;
    struct device *device;  // char device
    struct hpvbd *dev;
    unsigned int index;
    int open_count;
    struct shared_area *sa;
    struct blk_mq_tags **tags;
    spinlock_t q_lock;
    wait_queue_head_t poll_wait;
};

struct hpvbd {
	struct list_head list;
	unsigned int index;
	struct request_queue *q;
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	struct hrtimer timer;
	unsigned int queue_depth;
	spinlock_t lock;

	struct hpvbd_queue *queues;
	unsigned int nr_queues;
    sector_t size;
};

static LIST_HEAD(hpvbd_list);
static struct mutex lock;
static int hpvbd_major;
static int hpvbd_indexes;

struct completion_queue {
	struct llist_head list;
	struct hrtimer timer;
};

/*
 * These are per-cpu for now, they will need to be configured by the
 * complete_queues parameter and appropriately mapped.
 */
static DEFINE_PER_CPU(struct completion_queue, completion_queues);

enum {
	HPVBD_IRQ_NONE		= 0,
	HPVBD_IRQ_SOFTIRQ	= 1,
	HPVBD_IRQ_TIMER		= 2,
};

enum {
	HPVBD_Q_BIO		= 0,
	HPVBD_Q_RQ		= 1,
	HPVBD_Q_MQ		= 2,
};

static int submit_queues;
module_param(submit_queues, int, S_IRUGO);
MODULE_PARM_DESC(submit_queues, "Number of submission queues");

static int home_node = NUMA_NO_NODE;
module_param(home_node, int, S_IRUGO);
MODULE_PARM_DESC(home_node, "Home node for the device");

static int queue_mode = HPVBD_Q_MQ;
module_param(queue_mode, int, S_IRUGO);
MODULE_PARM_DESC(queue_mode, "Block interface to use (0=bio,1=rq,2=multiqueue)");

static int gb = 1;
module_param(gb, int, S_IRUGO);
MODULE_PARM_DESC(gb, "Size in GB");

static int bs = 512;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

static int nr_devices = 1;
module_param(nr_devices, int, S_IRUGO);
MODULE_PARM_DESC(nr_devices, "Number of devices to register");

static int irqmode = HPVBD_IRQ_SOFTIRQ;
module_param(irqmode, int, S_IRUGO);
MODULE_PARM_DESC(irqmode, "IRQ completion handler. 0-none, 1-softirq, 2-timer");

static int completion_nsec = 10000;
module_param(completion_nsec, int, S_IRUGO);
MODULE_PARM_DESC(completion_nsec, "Time in ns to complete a request in hardware. Default: 10,000ns");

static int hw_queue_depth = 16;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

static bool use_per_node_hctx = false;
module_param(use_per_node_hctx, bool, S_IRUGO);
MODULE_PARM_DESC(use_per_node_hctx, "Use per-node allocation for hardware context queues. Default: false");

static void put_tag(struct hpvbd_queue *nq, unsigned int tag)
{
	clear_bit_unlock(tag, nq->tag_map);

	if (waitqueue_active(&nq->wait))
		wake_up(&nq->wait);
}

static unsigned int get_tag(struct hpvbd_queue *nq)
{
	unsigned int tag;

	do {
		tag = find_first_zero_bit(nq->tag_map, nq->queue_depth);
		if (tag >= nq->queue_depth)
			return -1U;
	} while (test_and_set_bit_lock(tag, nq->tag_map));

	return tag;
}

static void free_cmd(struct hpvbd_cmd *cmd)
{
	put_tag(cmd->nq, cmd->tag);
}

static struct hpvbd_cmd *__alloc_cmd(struct hpvbd_queue *nq)
{
	struct hpvbd_cmd *cmd;
	unsigned int tag;

	tag = get_tag(nq);
	if (tag != -1U) {
		cmd = &nq->cmds[tag];
		cmd->tag = tag;
		cmd->nq = nq;
		return cmd;
	}

	return NULL;
}

static struct hpvbd_cmd *alloc_cmd(struct hpvbd_queue *nq, int can_wait)
{
	struct hpvbd_cmd *cmd;
	DEFINE_WAIT(wait);

	cmd = __alloc_cmd(nq);
	if (cmd || !can_wait)
		return cmd;

	do {
		prepare_to_wait(&nq->wait, &wait, TASK_UNINTERRUPTIBLE);
		cmd = __alloc_cmd(nq);
		if (cmd)
			break;

		io_schedule();
	} while (1);

	finish_wait(&nq->wait, &wait);
	return cmd;
}

static void end_cmd(struct hpvbd_cmd *cmd)
{
	switch (queue_mode)  {
	case HPVBD_Q_MQ:
		blk_mq_end_request(cmd->rq, 0);
		return;
	case HPVBD_Q_RQ:
		INIT_LIST_HEAD(&cmd->rq->queuelist);
		blk_end_request_all(cmd->rq, 0);
		break;
	case HPVBD_Q_BIO:
		bio_endio(cmd->bio, 0);
		break;
	}

	free_cmd(cmd);
}

static enum hrtimer_restart hpvbd_cmd_timer_expired(struct hrtimer *timer)
{
	struct completion_queue *cq;
	struct llist_node *entry;
	struct hpvbd_cmd *cmd;

	cq = &per_cpu(completion_queues, smp_processor_id());

	while ((entry = llist_del_all(&cq->list)) != NULL) {
		entry = llist_reverse_order(entry);
		do {
			cmd = container_of(entry, struct hpvbd_cmd, ll_list);
			entry = entry->next;
			end_cmd(cmd);
		} while (entry);
	}

	return HRTIMER_NORESTART;
}

static void hpvbd_cmd_end_timer(struct hpvbd_cmd *cmd)
{
	struct completion_queue *cq = &per_cpu(completion_queues, get_cpu());

	cmd->ll_list.next = NULL;
	if (llist_add(&cmd->ll_list, &cq->list)) {
		ktime_t kt = ktime_set(0, completion_nsec);

		hrtimer_start(&cq->timer, kt, HRTIMER_MODE_REL);
	}

	put_cpu();
}

static void hpvbd_softirq_done_fn(struct request *rq)
{
	if (queue_mode == HPVBD_Q_MQ)
		end_cmd(blk_mq_rq_to_pdu(rq));
	else
		end_cmd(rq->special);
}

static void *alloc_user_buffer(struct shared_area *sa, unsigned int tag, unsigned int len)
{
    char *buffer;
    BUG_ON(tag >= hw_queue_depth);
    BUG_ON(len > (HPVBD_REQ_MAX_SECTORS << 9));

    buffer = (char *)(sa->buffer + sa->databuf_off + tag * (HPVBD_REQ_MAX_SECTORS << 9));
    return buffer;
}

static void copy_to_user_buffer(struct hpvbd_queue *nq, struct request *req, struct hpvbd_user_request *cmnd)
{
    struct bio_vec *bvec;
    struct req_iterator iter;
    void *src, *dst;
    unsigned len = 0;

    dst = alloc_user_buffer(nq->sa, req->tag, blk_rq_bytes(req));

    rq_for_each_segment(bvec, req, iter) {
        src = kmap(bvec->bv_page) + bvec->bv_offset;
        memcpy(dst + len, src, bvec->bv_len);
        len += bvec->bv_len;
        kunmap(bvec->bv_page);
    }

    cmnd->rw.buf_off = (char *)dst - nq->sa->buffer;
}

static void copy_from_user_buffer(struct hpvbd_queue *nq, struct request *req, struct hpvbd_user_request *cmnd)
{
    struct bio_vec *bvec;
    struct req_iterator iter;
    void *src, *dst;
    unsigned len = 0;

    src = nq->sa->buffer + cmnd->rw.buf_off;

    rq_for_each_segment(bvec, req, iter) {
        dst = kmap(bvec->bv_page) + bvec->bv_offset;
        memcpy(dst, src + len, bvec->bv_len);
        len += bvec->bv_len;
        kunmap(bvec->bv_page);
    }
}

static void hpvbd_init_user_cmd(struct hpvbd_queue *nq, struct hpvbd_cmd *iod, struct hpvbd_user_request *cmnd)
{
    struct request *req = iod->rq;

    memset(cmnd, 0, sizeof(*cmnd));
    cmnd->rw.opcode = (rq_data_dir(req) ? hpvbd_cmd_write : hpvbd_cmd_read);
    cmnd->rw.tag = req->tag;
    cmnd->rw.slba = blk_rq_pos(req);
    cmnd->rw.length = blk_rq_bytes(req);

    if (req->nr_phys_segments == 0)
        return;
    
    /*
    {
        struct bio_vec *bvec;
        struct req_iterator iter;
        int i;

        i = 0;
        rq_for_each_segment(bvec, req, iter) {
            struct hpvbd_iovec *nvec = &cmnd->rw.iovec[i++];
            nvec->phys_addr = page_to_phys(bvec->bv_page) + bvec->bv_offset;
            nvec->len = bvec->bv_len;

            if (i >= HPVBD_REQ_MAX_SEGMENTS) {
                hpvbd_dbg(nq->dev, "request exceeds max segments");
                break;
            }
        }
        cmnd->rw.nr_iovec = i;
    }
    */

    if (cmnd->rw.opcode == hpvbd_cmd_write) {
        copy_to_user_buffer(nq, req, cmnd);
    } else if (cmnd->rw.opcode == hpvbd_cmd_read) {
        void *dst = alloc_user_buffer(nq->sa, req->tag, blk_rq_bytes(req));
        cmnd->rw.buf_off = (char *)dst - nq->sa->buffer;
    }
}

static inline void notify_user_new_reqeust(struct hpvbd_queue *nq)
{
    wake_up_interruptible(&nq->poll_wait);
}

static int hpvbd_mq_handle_cmd(struct hpvbd_cmd *cmd)
{
    int rc;
    struct hpvbd_queue *nq = cmd->nq;

    if (cmd->rq->cmd_flags & REQ_DISCARD) {
	    blk_mq_complete_request(cmd->rq, 0);
        return BLK_MQ_RQ_QUEUE_OK;
    }

    hpvbd_init_user_cmd(nq, cmd, &cmd->cmd);

    hpvbd_dbg(nq->dev, "enqueue tag = %d, opcode = %d\n", cmd->rq->tag, cmd->cmd.rw.opcode);

    spin_lock_irq(&nq->q_lock);
    rc = hpvbd_ring_buffer_enqueue(&nq->sa->sq, &cmd->cmd, 0);
    spin_unlock_irq(&nq->q_lock);

    if (rc != 0) {
        hpvbd_dbg(nq->dev, "enqueue failed, queue busy\n");
        return BLK_MQ_RQ_QUEUE_BUSY;
    }

    notify_user_new_reqeust(nq);
    return BLK_MQ_RQ_QUEUE_OK;
}

static inline int hpvbd_handle_cmd(struct hpvbd_cmd *cmd)
{
    int rc = BLK_MQ_RQ_QUEUE_OK;

	/* Complete IO by inline, softirq or timer */
	switch (irqmode) {
	case HPVBD_IRQ_SOFTIRQ:
		switch (queue_mode)  {
		case HPVBD_Q_MQ:
            rc = hpvbd_mq_handle_cmd(cmd);
			break;
		case HPVBD_Q_RQ:
			blk_complete_request(cmd->rq);
			break;
		case HPVBD_Q_BIO:
			/*
			 * XXX: no proper submitting cpu information available.
			 */
			end_cmd(cmd);
			break;
		}
		break;
	case HPVBD_IRQ_NONE:
		end_cmd(cmd);
		break;
	case HPVBD_IRQ_TIMER:
		hpvbd_cmd_end_timer(cmd);
		break;
	}

    return rc;
}

static struct hpvbd_queue *hpvbd_to_queue(struct hpvbd *hpvbd)
{
	int index = 0;

	if (hpvbd->nr_queues != 1)
		index = raw_smp_processor_id() / ((nr_cpu_ids + hpvbd->nr_queues - 1) / hpvbd->nr_queues);

	return &hpvbd->queues[index];
}

static void hpvbd_queue_bio(struct request_queue *q, struct bio *bio)
{
	struct hpvbd *hpvbd = q->queuedata;
	struct hpvbd_queue *nq = hpvbd_to_queue(hpvbd);
	struct hpvbd_cmd *cmd;

	cmd = alloc_cmd(nq, 1);
	cmd->bio = bio;

	hpvbd_handle_cmd(cmd);
}

static int hpvbd_rq_prep_fn(struct request_queue *q, struct request *req)
{
	struct hpvbd *hpvbd = q->queuedata;
	struct hpvbd_queue *nq = hpvbd_to_queue(hpvbd);
	struct hpvbd_cmd *cmd;

	cmd = alloc_cmd(nq, 0);
	if (cmd) {
		cmd->rq = req;
		req->special = cmd;
		return BLKPREP_OK;
	}

	return BLKPREP_DEFER;
}

static void hpvbd_request_fn(struct request_queue *q)
{
	struct request *rq;

	while ((rq = blk_fetch_request(q)) != NULL) {
		struct hpvbd_cmd *cmd = rq->special;

		spin_unlock_irq(q->queue_lock);
		hpvbd_handle_cmd(cmd);
		spin_lock_irq(q->queue_lock);
	}
}

static int hpvbd_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct hpvbd_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);

	cmd->rq = bd->rq;
	cmd->nq = hctx->driver_data;

	blk_mq_start_request(bd->rq);

	return hpvbd_handle_cmd(cmd);
}

static const struct attribute_group *hpvbd_queue_attr_groups[] = {
    NULL,
};

static struct shared_area *create_shared_data(void)
{
    unsigned long len;
    struct shared_area *sa;
    unsigned long ring_buffer_size;

    ring_buffer_size = hpvbd_ring_buffer_size_needed(hw_queue_depth, sizeof(struct hpvbd_user_request));

    len = sizeof(struct shared_area) + ring_buffer_size + (HPVBD_REQ_MAX_SECTORS << 9) * hw_queue_depth;
    len = PAGE_ALIGN(len);
	pr_info("hpvbd: shared area len = %lu\n", len);

    sa = vmalloc(len);
    BUG_ON(sa == NULL);
    sa->sa_size = len;

    hpvbd_ring_buffer_init(&sa->sq, hw_queue_depth, sizeof(struct hpvbd_user_request), sa->buffer);
    sa->databuf_off = ring_buffer_size;

    return sa;
}

static void hpvbd_init_queue(struct hpvbd *hpvbd, struct hpvbd_queue *nq, unsigned int index)
{
	BUG_ON(!hpvbd);
	BUG_ON(!nq);

	init_waitqueue_head(&nq->wait);
	nq->queue_depth = hpvbd->queue_depth;

    nq->dev = hpvbd;
    nq->index = index;
    spin_lock_init(&nq->q_lock);
    init_waitqueue_head(&nq->poll_wait);

    hpvbd_info(nq->dev, "vmalloc nq->sa\n");
    nq->sa = create_shared_data();

    nq->device = device_create_with_groups(hpvbd_class, NULL,
            MKDEV(hpvbd_char_major, HPVBD_MK_MINOR(hpvbd->index, index)),
            nq, hpvbd_queue_attr_groups,
            "hpvbd%dq%d", hpvbd->index, index);
}

static int hpvbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int index)
{
	struct hpvbd *hpvbd = data;
	struct hpvbd_queue *nq = &hpvbd->queues[index];

    if (!nq->tags) {
        nq->tags = &hpvbd->tag_set.tags[index];
    }

	hctx->driver_data = nq;
	hpvbd_init_queue(hpvbd, nq, index);
	hpvbd->nr_queues++;

	return 0;
}

static struct blk_mq_ops hpvbd_mq_ops = {
	.queue_rq       = hpvbd_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_hctx	= hpvbd_init_hctx,
	.complete	= hpvbd_softirq_done_fn,
};

static void hpvbd_deinit_queue(struct hpvbd *hpvbd, struct hpvbd_queue *nq)
{
    if (nq->sa) {
        hpvbd_info(nq->dev, "vfree nq->sa\n");
        vfree(nq->sa);
        nq->sa = NULL;
    }

    device_destroy(hpvbd_class, MKDEV(hpvbd_char_major, (hpvbd->index << 8) | nq->index));
}

static void hpvbd_del_dev(struct hpvbd *hpvbd)
{
    int i;
	list_del_init(&hpvbd->list);

	for (i = 0; i < hpvbd->nr_queues; i++) {
		struct hpvbd_queue *nq = &hpvbd->queues[i];
		hpvbd_deinit_queue(hpvbd, nq);
    }

	del_gendisk(hpvbd->disk);
	blk_cleanup_queue(hpvbd->q);
	if (queue_mode == HPVBD_Q_MQ)
		blk_mq_free_tag_set(&hpvbd->tag_set);
	put_disk(hpvbd->disk);
	kfree(hpvbd);
}

static int hpvbd_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void hpvbd_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations hpvbd_fops = {
	.owner =	THIS_MODULE,
	.open =		hpvbd_open,
	.release =	hpvbd_release,
};

static int setup_commands(struct hpvbd_queue *nq)
{
	struct hpvbd_cmd *cmd;
	int i, tag_size;

	nq->cmds = kzalloc(nq->queue_depth * sizeof(*cmd), GFP_KERNEL);
	if (!nq->cmds)
		return -ENOMEM;

	tag_size = ALIGN(nq->queue_depth, BITS_PER_LONG) / BITS_PER_LONG;
	nq->tag_map = kzalloc(tag_size * sizeof(unsigned long), GFP_KERNEL);
	if (!nq->tag_map) {
		kfree(nq->cmds);
		return -ENOMEM;
	}

	for (i = 0; i < nq->queue_depth; i++) {
		cmd = &nq->cmds[i];
		INIT_LIST_HEAD(&cmd->list);
		cmd->ll_list.next = NULL;
		cmd->tag = -1U;
	}

	return 0;
}

static void cleanup_queue(struct hpvbd_queue *nq)
{
	kfree(nq->tag_map);
	kfree(nq->cmds);
}

static void cleanup_queues(struct hpvbd *hpvbd)
{
	int i;

	for (i = 0; i < hpvbd->nr_queues; i++)
		cleanup_queue(&hpvbd->queues[i]);

	kfree(hpvbd->queues);
}

static int setup_queues(struct hpvbd *hpvbd)
{
	hpvbd->queues = kzalloc(submit_queues * sizeof(struct hpvbd_queue),
								GFP_KERNEL);
	if (!hpvbd->queues)
		return -ENOMEM;

	hpvbd->nr_queues = 0;
	hpvbd->queue_depth = hw_queue_depth;

	return 0;
}

static int init_driver_queues(struct hpvbd *hpvbd)
{
	struct hpvbd_queue *nq;
	int i, ret = 0;

	for (i = 0; i < submit_queues; i++) {
		nq = &hpvbd->queues[i];

		hpvbd_init_queue(hpvbd, nq, (unsigned int)i);

		ret = setup_commands(nq);
		if (ret)
			goto err_queue;
		hpvbd->nr_queues++;
	}

	return 0;
err_queue:
	cleanup_queues(hpvbd);
	return ret;
}

static int hpvbd_add_dev(void)
{
	struct gendisk *disk;
	struct hpvbd *hpvbd;
	sector_t size;
	int rv;

	hpvbd = kzalloc_node(sizeof(*hpvbd), GFP_KERNEL, home_node);
	if (!hpvbd) {
		rv = -ENOMEM;
		goto out;
	}

	spin_lock_init(&hpvbd->lock);

	rv = setup_queues(hpvbd);
	if (rv)
		goto out_free_hpvbd;

	if (queue_mode == HPVBD_Q_MQ) {
		hpvbd->tag_set.ops = &hpvbd_mq_ops;
		hpvbd->tag_set.nr_hw_queues = submit_queues;
		hpvbd->tag_set.queue_depth = hw_queue_depth;
		hpvbd->tag_set.numa_node = home_node;
		hpvbd->tag_set.cmd_size	= sizeof(struct hpvbd_cmd);
		hpvbd->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
		hpvbd->tag_set.driver_data = hpvbd;

		rv = blk_mq_alloc_tag_set(&hpvbd->tag_set);
		if (rv)
			goto out_cleanup_queues;

		hpvbd->q = blk_mq_init_queue(&hpvbd->tag_set);
		if (!hpvbd->q) {
			rv = -ENOMEM;
			goto out_cleanup_tags;
		}
	} else if (queue_mode == HPVBD_Q_BIO) {
		hpvbd->q = blk_alloc_queue_node(GFP_KERNEL, home_node);
		if (!hpvbd->q) {
			rv = -ENOMEM;
			goto out_cleanup_queues;
		}
		blk_queue_make_request(hpvbd->q, hpvbd_queue_bio);
		init_driver_queues(hpvbd);
	} else {
		hpvbd->q = blk_init_queue_node(hpvbd_request_fn, &hpvbd->lock, home_node);
		if (!hpvbd->q) {
			rv = -ENOMEM;
			goto out_cleanup_queues;
		}
		blk_queue_prep_rq(hpvbd->q, hpvbd_rq_prep_fn);
		blk_queue_softirq_done(hpvbd->q, hpvbd_softirq_done_fn);
		init_driver_queues(hpvbd);
	}

	hpvbd->q->queuedata = hpvbd;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, hpvbd->q);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, hpvbd->q);

	disk = hpvbd->disk = alloc_disk_node(1, home_node);
	if (!disk) {
		rv = -ENOMEM;
		goto out_cleanup_blk_queue;
	}

	mutex_lock(&lock);
	list_add_tail(&hpvbd->list, &hpvbd_list);
	hpvbd->index = hpvbd_indexes++;
	mutex_unlock(&lock);

	blk_queue_logical_block_size(hpvbd->q, bs);
	blk_queue_physical_block_size(hpvbd->q, bs);
	blk_queue_max_segments(hpvbd->q, HPVBD_REQ_MAX_SEGMENTS);
    blk_queue_max_hw_sectors(hpvbd->q, HPVBD_REQ_MAX_SECTORS);

	size = gb * 1024 * 1024 * 1024ULL;
	sector_div(size, bs);
	set_capacity(disk, size);
    hpvbd->size = size;

	disk->flags |= GENHD_FL_EXT_DEVT;
	disk->major		= hpvbd_major;
	disk->first_minor	= hpvbd->index;
	disk->fops		= &hpvbd_fops;
	disk->private_data	= hpvbd;
	disk->queue		= hpvbd->q;
	sprintf(disk->disk_name, "hpvbd%d", hpvbd->index);
	add_disk(disk);
	return 0;

out_cleanup_blk_queue:
	blk_cleanup_queue(hpvbd->q);
out_cleanup_tags:
	if (queue_mode == HPVBD_Q_MQ)
		blk_mq_free_tag_set(&hpvbd->tag_set);
out_cleanup_queues:
	cleanup_queues(hpvbd);
out_free_hpvbd:
	kfree(hpvbd);
out:
	return rv;
}

// TODO: exclusive open only
static int hpvbd_queue_open(struct inode *inode, struct file *file)
{
    int index = HPVBD_BLK_INDEX(iminor(inode));
    int queue_idx = HPVBD_QUEUE_INDEX(iminor(inode));
    struct hpvbd *hpvbd;
    struct hpvbd_queue *nq;
    int ret = -ENODEV;

	mutex_lock(&lock);
    list_for_each_entry(hpvbd, &hpvbd_list, list) {
        if (hpvbd->index != index)
            continue;

        /* TODO: check hpvbd kref and inc */
        file->private_data = nq = &hpvbd->queues[queue_idx];
        nq->open_count++;
        ret = 0;
        break;
    }
	mutex_unlock(&lock);
    return ret;
}

static int hpvbd_queue_release(struct inode *inode, struct file *file)
{
    /* TODO: dec hpvbd->kref */
    struct hpvbd_queue *nq = file->private_data;
    if (--nq->open_count != 0)
        return 0;

    return 0;
}


static long hpvbd_ioctl_io_cmd(struct hpvbd_queue *nq, struct hpvbd_ioctl_io __user *ucmd)
{
    struct hpvbd_ioctl_io cmd;
    struct request *req;
	struct hpvbd_cmd *cmnd;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    hpvbd_dbg(nq->dev, "receive tag = %d\n", cmd.tag);

    req = blk_mq_tag_to_rq(*nq->tags, cmd.tag);
    cmnd = blk_mq_rq_to_pdu(req);

    if (cmnd->cmd.rw.opcode == hpvbd_cmd_read) {
        copy_from_user_buffer(nq, req, &cmnd->cmd);
    }

	blk_mq_complete_request(req, 0);
    return 0;
}

static long hpvbd_ioctl_admin_cmd(struct hpvbd_queue *nq, struct hpvbd_ioctl_admin __user *ucmd)
{
    int rc = 0;
    struct hpvbd_ioctl_admin cmd;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    switch (cmd.opcode) {
    case hpvbd_admin_queue_info:
        cmd.queue_info.sa_size = nq->sa->sa_size;
        cmd.queue_info.disk_sectors = nq->dev->size;
        break;
    default:
        rc = -ENOIOCTLCMD;
        break;
    }

    if (copy_to_user(ucmd, &cmd, sizeof(cmd)))
        return -EFAULT;
    return rc;
}

static long hpvbd_queue_ioctl(struct file *file, unsigned int cmd,
                unsigned long arg)
{
    struct hpvbd_queue *nq = file->private_data;

    switch (cmd) {
    case HPVBD_IOCTL_IO_CMD:
        return hpvbd_ioctl_io_cmd(nq, (struct hpvbd_ioctl_io *)arg);
    case HPVBD_IOCTL_ADMIN_CMD:
        return hpvbd_ioctl_admin_cmd(nq, (struct hpvbd_ioctl_admin *)arg);
    default:
        return -ENOTTY;
    }
    return 0;
}

static void hpvbd_vm_open(struct vm_area_struct *vma)
{
    struct hpvbd_queue *nq = vma->vm_private_data;
    hpvbd_info(nq->dev, "vm open\n");
}

static void hpvbd_vm_close(struct vm_area_struct *vma)
{
    struct hpvbd_queue *nq = vma->vm_private_data;
    hpvbd_info(nq->dev, "vm close\n");
}


static struct vm_operations_struct hpvbd_vm_ops = {
    .open   = hpvbd_vm_open,
    .close  = hpvbd_vm_close,
};

static int hpvbd_queue_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long len = vma->vm_end - vma->vm_start, offset, pfn;
    char *mem;
    struct page *page;
    struct hpvbd_queue *nq = file->private_data;

    mem = (char *)nq->sa;
    len = len > nq->sa->sa_size ? nq->sa->sa_size : len;

    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_ops = &hpvbd_vm_ops;
    vma->vm_private_data = (void *)nq;

    for (offset = 0; offset < len; offset += PAGE_SIZE) {
        page = vmalloc_to_page(mem + offset);
        get_page(page);
        pfn = page_to_pfn(page);

        if (remap_pfn_range(vma, vma->vm_start + offset, pfn, PAGE_SIZE,
                        vma->vm_page_prot))
            return -EAGAIN; // TODO
    }

    hpvbd_vm_open(vma);
    return 0;
}

static unsigned int hpvbd_queue_poll(struct file *file, poll_table *wait)
{
    struct hpvbd_queue *nq = file->private_data;
    unsigned mask = 0;

    poll_wait(file, &nq->poll_wait, wait);
    mask |= POLLIN | POLLRDNORM;
    return mask;
}

static const struct file_operations hpvbd_queue_fops = {
    .owner      = THIS_MODULE,
    .open       = hpvbd_queue_open,
    .release    = hpvbd_queue_release,
    .unlocked_ioctl = hpvbd_queue_ioctl,
    .compat_ioctl   = hpvbd_queue_ioctl,
    .mmap       = hpvbd_queue_mmap,
    .poll       = hpvbd_queue_poll,
};

static int __init hpvbd_init(void)
{
	unsigned int i;
    int result;

	if (bs > PAGE_SIZE) {
		pr_warn("hpvbd_blk: invalid block size\n");
		pr_warn("hpvbd_blk: defaults block size to %lu\n", PAGE_SIZE);
		bs = PAGE_SIZE;
	}

	if (queue_mode == HPVBD_Q_MQ && use_per_node_hctx) {
		if (submit_queues < nr_online_nodes) {
			pr_warn("hpvbd_blk: submit_queues param is set to %u.",
							nr_online_nodes);
			submit_queues = nr_online_nodes;
		}
	} else if (submit_queues > nr_cpu_ids)
		submit_queues = nr_cpu_ids;
	else if (!submit_queues)
		submit_queues = 1;

	mutex_init(&lock);

	/* Initialize a separate list for each CPU for issuing softirqs */
	for_each_possible_cpu(i) {
		struct completion_queue *cq = &per_cpu(completion_queues, i);

		init_llist_head(&cq->list);

		if (irqmode != HPVBD_IRQ_TIMER)
			continue;

		hrtimer_init(&cq->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cq->timer.function = hpvbd_cmd_timer_expired;
	}

	hpvbd_major = register_blkdev(0, "hpvbd");
	if (hpvbd_major < 0)
		return hpvbd_major;

    result = __register_chrdev(hpvbd_char_major, 0, HPVBD_MINORS, "hpvbd",
            &hpvbd_queue_fops);
    if (result < 0)
        goto unregister_blkdev;
    else if (result > 0)
        hpvbd_char_major = result;

    hpvbd_class = class_create(THIS_MODULE, "hpvbd");
    if (IS_ERR(hpvbd_class)) {
        result = PTR_ERR(hpvbd_class);
        goto unregister_chrdev;
    }

	for (i = 0; i < nr_devices; i++) {
		if (hpvbd_add_dev()) {
            result = -EINVAL;
            goto unregister_chrdev;
		}
	}

	pr_info("hpvbd: module loaded\n");
	return 0;

unregister_chrdev:
    __unregister_chrdev(hpvbd_char_major, 0, HPVBD_MINORS, "hpvbd");
unregister_blkdev:
	unregister_blkdev(hpvbd_major, "hpvbd");
    return result;
}

static void __exit hpvbd_exit(void)
{
	struct hpvbd *hpvbd;

	unregister_blkdev(hpvbd_major, "hpvbd");

	mutex_lock(&lock);
	while (!list_empty(&hpvbd_list)) {
		hpvbd = list_entry(hpvbd_list.next, struct hpvbd, list);
		hpvbd_del_dev(hpvbd);
	}
	mutex_unlock(&lock);

    class_destroy(hpvbd_class);
    __unregister_chrdev(hpvbd_char_major, 0, HPVBD_MINORS, "hpvbd");
	pr_info("hpvbd: module unloaded\n");
}

module_init(hpvbd_init);
module_exit(hpvbd_exit);

MODULE_AUTHOR("Jens Axboe <jaxboe@fusionio.com>");
MODULE_LICENSE("GPL");
