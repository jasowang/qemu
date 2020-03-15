/*
 * vhost-vfio
 *
 *  Copyright(c) 2017-2018 Intel Corporation. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <linux/vhost.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"
#include "hw/virtio/virtio-net.h"
#include "hw/virtio/vhost-vfio.h"
#include "qemu/main-loop.h"

extern AddressSpace address_space_memory;

// TODO: move to linux/vhost.h
struct vhost_vfio_op {
    __u64 request;
    __u32 flags;
    __u32 size;
    union {
        __u64 u64;
        struct vhost_vring_state state;
        struct vhost_vring_file file;
        struct vhost_vring_addr addr;
        struct vhost_memory memory;
    } payload;
};
#define VHOST_VFIO_OP_HDR_SIZE (offsetof(struct vhost_vfio_op, payload))
#define VHOST_VFIO_NEED_REPLY 0x1

struct vhost_mdev_config {
	__u32 off;
	__u32 len;
	__u8 buf[0];
};


/* Get the device id. The device ids follow the same definition of
 * the device id defined in virtio-spec. */
#define VHOST_MDEV_GET_DEVICE_ID	_IOR(VHOST_VIRTIO, 0x70, __u32)
/* Get and set the status. The status bits follow the same definition
 * of the device status defined in virtio-spec. */
#define VHOST_MDEV_GET_STATUS		_IOR(VHOST_VIRTIO, 0x71, __u8)
#define VHOST_MDEV_SET_STATUS		_IOW(VHOST_VIRTIO, 0x72, __u8)
/* Get and set the device config. The device config follows the same
 * definition of the device config defined in virtio-sec */
#define VHOST_MDEV_GET_CONFIG		_IOR(VHOST_VIRTIO, 0x73, struct vhost_mdev_config)
#define VHOST_MDEV_SET_CONFIG		_IOW(VHOST_VIRTIO, 0x74, struct vhost_mdev_config)
/* Enable/disable the ring. */
#define VHOST_MDEV_SET_VRING_ENABLE	_IOW(VHOST_VIRTIO, 0x75, struct vhost_vring_state)
/* Get the max ring size. */
#define VHOST_MDEV_GET_VRING_NUM	_IOR(VHOST_VIRTIO, 0x76, __u16)

struct vhost_vfio {
    VhostVFIO *vfio;
    MemoryListener listener;
};

// -- end here


// -----------------
// XXX: to be removed
#include <linux/kvm.h>
#include "sysemu/kvm.h"
extern int vfio_kvm_device_fd;

static int vhost_vfio_kvm_add_vfio_group(VhostVFIO *v)
{
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_ADD,
        .addr = (uint64_t)(uintptr_t)&v->group_fd,
    };
    int ret;

again:
    if (vfio_kvm_device_fd < 0) {
        struct kvm_create_device cd = {
            .type = KVM_DEV_TYPE_VFIO,
        };

        ret = kvm_vm_ioctl(kvm_state, KVM_CREATE_DEVICE, &cd);
        if (ret < 0) {
            if (errno == EBUSY) {
                goto again;
            }
            return -1;
        }

        vfio_kvm_device_fd = cd.fd;
    }

    ret = ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr);
    if (ret < 0) {
        return -1;
    }

    kvm_irqchip_commit_routes(kvm_state);

    return 0;
}
// -----------------

static bool vhost_vdpa_listener_skipped_section(MemoryRegionSection *section)
{
    return (!memory_region_is_ram(section->mr) &&
            !memory_region_is_iommu(section->mr)) ||
           /*
            * Sizing an enabled 64-bit BAR can cause spurious mappings to
            * addresses in the upper part of the 64-bit address space.  These
            * are never accessed by the CPU and beyond the address width of
            * some IOMMU hardware.  TODO: VFIO should tell us the IOMMU width.
            */
           section->offset_within_address_space & (1ULL << 63);
}

static int vhost_vdpa_dma_map(struct vhost_vfio *v, hwaddr iova, hwaddr size,
                              void *vaddr, bool readonly)
{
    VhostVFIO *vfio = v->vfio;
    struct vhost_msg_v2 msg;
    int fd = vfio->device_fd;
    int ret = 0;

    msg.type = VHOST_IOTLB_MSG_V2;
    msg.iotlb.iova = iova;
    msg.iotlb.size = size;
    msg.iotlb.uaddr = (uint64_t)vaddr;
    msg.iotlb.perm = readonly ? VHOST_ACCESS_RO : VHOST_ACCESS_RW;
    msg.iotlb.type = VHOST_IOTLB_UPDATE;

    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
        fprintf(stderr, "failed to write, fd=%d, errno=%d (%s)\n",
                fd, errno, strerror(errno));
        exit(1);
    }

    return ret;
}

static int vhost_vdpa_dma_unmap(struct vhost_vfio *v, hwaddr iova,
                                hwaddr size)
{
    VhostVFIO *vfio = v->vfio;
    struct vhost_msg_v2 msg;
    int fd = vfio->device_fd;
    int ret = 0;

    msg.type = VHOST_IOTLB_MSG_V2;
    msg.iotlb.iova = iova;
    msg.iotlb.size = size;
    msg.iotlb.type = VHOST_IOTLB_INVALIDATE;

    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
        printf("failed to write, fd=%d, errno=%d (%s)\n",
               fd, errno, strerror(errno));
        exit(1);
    }

    return ret;
}

static void vhost_vdpa_listener_region_add(MemoryListener *listener,
                                           MemoryRegionSection *section)
{
    struct vhost_vfio *v = container_of(listener, struct vhost_vfio, listener);
    hwaddr iova;
    Int128 llend, llsize;
    void *vaddr;
    int ret;

    if (vhost_vdpa_listener_skipped_section(section)) {
#if 0
        fprintf(stderr, "skip start %"PRIx64" end %"PRIx64"\n",
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size,
                int128_one())));
#endif
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(TARGET_PAGE_MASK));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }

    memory_region_ref(section->mr);

    /* Here we assume that memory_region_is_ram(section->mr)==true */

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region +
            (iova - section->offset_within_address_space);

    llsize = int128_sub(llend, int128_make64(iova));
    fprintf(stderr, "region add iova %"PRIx64" size %"PRIx64" vaddr %"PRIx64"\n",
            iova, int128_get64(llsize), (hwaddr)vaddr);

    ret = vhost_vdpa_dma_map(v, iova, int128_get64(llsize),
                             vaddr, section->readonly);
    if (ret) {
        fprintf(stderr, "vhost vdpa map fail!\n");
        if (memory_region_is_ram_device(section->mr)) {
            /* Allow unexpected mappings not to be fatal for RAM devices */
            fprintf(stderr, "map ram fail!\n");
            exit(1);
            return;
        }
        goto fail;
    }

    return;

fail:
    if (memory_region_is_ram_device(section->mr)) {
        error_report("failed to vfio_dma_map. pci p2p may not work");
        return;
    }
    /*
     * On the initfn path, store the first error in the container so we
     * can gracefully fail.  Runtime, there's not much we can do other
     * than throw a hardware error.
     */
    fprintf(stderr, "vhost-vdpa: DMA mapping failed, unable to continue");
    exit(1);
}

static void vhost_vdpa_listener_region_del(MemoryListener *listener,
                                           MemoryRegionSection *section)
{
    struct vhost_vfio *v = container_of(listener, struct vhost_vfio, listener);
    hwaddr iova;
    Int128 llend, llsize;
    int ret;
    bool try_unmap = true;

    if (vhost_vdpa_listener_skipped_section(section)) {
#if 0
        fprintf(stderr, "skip start %"PRIx64" end %"PRIx64"\n",
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size,
                int128_one())));
#endif
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(TARGET_PAGE_MASK));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }

    llsize = int128_sub(llend, int128_make64(iova));

    if (try_unmap) {
        fprintf(stderr, "region del iova %"PRIx64" size %"PRIx64"\n",
                iova, int128_get64(llsize));
        ret = vhost_vdpa_dma_unmap(v, iova, int128_get64(llsize));
        if (ret) {
            fprintf(stderr, "vhost_vdpa dma unmap error!\n");
        }
    }

    memory_region_unref(section->mr);
}

static const MemoryListener vhost_vdpa_memory_listener = {
    .region_add = vhost_vdpa_listener_region_add,
    .region_del = vhost_vdpa_listener_region_del,
};

struct notify_arg {
    struct vhost_dev *dev;
    int qid;
};

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    struct vhost_vfio *v = dev->opaque;
    VhostVFIO *vfio = v->vfio;
    int fd = vfio->device_fd;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VFIO);

    return ioctl(fd, request, arg);
}

static int vhost_vfio_init(struct vhost_dev *dev, void *opaque)
{
    struct vhost_vfio *v;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VFIO);

    v = g_new0(struct vhost_vfio, 1);
    v->vfio = opaque;

    dev->opaque = v;

    v->listener = vhost_vdpa_memory_listener;
    memory_listener_register(&v->listener, &address_space_memory);

    vhost_vfio_kvm_add_vfio_group(v->vfio);

    return 0;
}

static int vhost_vfio_cleanup(struct vhost_dev *dev)
{
    struct vhost_vfio *v = dev->opaque;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VFIO);

    g_free(v);
    dev->opaque = NULL;

    return 0;
}

static int vhost_vfio_memslots_limit(struct vhost_dev *dev)
{
    int limit = 64; // XXX hardcoded for now

    return limit;
}

static int vhost_vfio_set_log_base(struct vhost_dev *dev, uint64_t base,
                                   struct vhost_log *log)
{
    return 0;
}

static int vhost_vfio_set_mem_table(struct vhost_dev *dev,
                                    struct vhost_memory *mem)
{
    fprintf(stderr, "dummy mem table!\n");

    if (mem->padding)
        return -1;

    return 0;
}

static int vhost_vfio_set_vring_addr(struct vhost_dev *dev,
                                     struct vhost_vring_addr *addr)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_ADDR, addr);
}

static int vhost_vfio_set_vring_num(struct vhost_dev *dev,
                                    struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_NUM, ring);
}

static int vhost_vfio_set_vring_base(struct vhost_dev *dev,
                                     struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_GET_VRING_BASE, ring);
}

static int vhost_vfio_get_vring_base(struct vhost_dev *dev,
                                     struct vhost_vring_state *ring)
{

    return vhost_kernel_call(dev, VHOST_GET_VRING_BASE, ring);
}

static int vhost_vfio_set_vring_kick(struct vhost_dev *dev,
                                     struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_KICK, file);
}

static int vhost_vfio_set_vring_call(struct vhost_dev *dev,
                                     struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_CALL, file);
}

static int vhost_vfio_set_features(struct vhost_dev *dev,
                                   uint64_t features)
{
    int ret;
    uint8_t status;
    uint32_t device_id;
    if (vhost_kernel_call(dev, VHOST_MDEV_GET_DEVICE_ID, &device_id)) {
	printf("%s get device id failed, errno=%d\n", __func__, errno);
    }

    status = 0;
    if (vhost_kernel_call(dev, VHOST_MDEV_SET_STATUS, &status)) {
	printf("%s reset failed, errno=%d\n", __func__, errno);
    }
    features |= (1ULL << VIRTIO_F_IOMMU_PLATFORM); // hack
    ret = vhost_kernel_call(dev, VHOST_SET_FEATURES, &features);
    if (ret) {
	printf("%s called, failed, errno=%d\n", __func__, errno);
        return ret;
    }
    status = VIRTIO_CONFIG_S_FEATURES_OK;
    return vhost_kernel_call(dev, VHOST_MDEV_SET_STATUS, &status);
}

static int vhost_vfio_get_features(struct vhost_dev *dev,
                                   uint64_t *features)
{
    return vhost_kernel_call(dev, VHOST_GET_FEATURES, features);
}

static int vhost_vfio_set_owner(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_SET_OWNER, NULL);
}

static int vhost_vfio_reset_device(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_RESET_OWNER, NULL);
}

static int vhost_vfio_get_vq_index(struct vhost_dev *dev, int idx)
{
    assert(idx >= dev->vq_index && idx < dev->vq_index + dev->nvqs);

    return idx - dev->vq_index;
}

static int vhost_vfio_set_vring_enable(struct vhost_dev *dev, int enable)
{
    int i;

    for (i = 0; i < dev->nvqs; ++i) {
        struct vhost_vring_state state = {
            .index = dev->vq_index + i,
            .num   = enable,
        };

	state.num = 1;

        vhost_kernel_call(dev, VHOST_MDEV_SET_VRING_ENABLE, &state);
    }

    return 0;
}

static int vhost_vfio_set_state(struct vhost_dev *dev, int state)
{
    uint8_t status = 0;
    int ret;


    if (state == VHOST_DEVICE_S_RUNNING) {
	    status |= VIRTIO_CONFIG_S_FEATURES_OK;
	    status |= VIRTIO_CONFIG_S_DRIVER_OK;
    }

    ret = vhost_kernel_call(dev, VHOST_MDEV_SET_STATUS, &status);
    if (ret) {
	    perror("SET_STATUS");
    }
    return ret;
}

static int vhost_vfio_migration_done(struct vhost_dev *dev, char* mac_addr)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VFIO);

    /* If guest supports GUEST_ANNOUNCE do nothing */
    if (virtio_has_feature(dev->acked_features, VIRTIO_NET_F_GUEST_ANNOUNCE)) {
        return 0;
    }

    return -1;
}

static void vhost_vdpa_set_iotlb_callback(struct vhost_dev *dev,
                                          int enabled)
{
    /* dummy */
}

const VhostOps vfio_ops = {
        .backend_type = VHOST_BACKEND_TYPE_VFIO,
        .vhost_backend_init = vhost_vfio_init,
        .vhost_backend_cleanup = vhost_vfio_cleanup,
        .vhost_backend_memslots_limit = vhost_vfio_memslots_limit,
        .vhost_set_log_base = vhost_vfio_set_log_base,
        .vhost_set_mem_table = vhost_vfio_set_mem_table,
        .vhost_set_vring_addr = vhost_vfio_set_vring_addr,
        .vhost_set_vring_endian = NULL,
        .vhost_set_vring_num = vhost_vfio_set_vring_num,
        .vhost_set_vring_base = vhost_vfio_set_vring_base,
        .vhost_get_vring_base = vhost_vfio_get_vring_base,
        .vhost_set_vring_kick = vhost_vfio_set_vring_kick,
        .vhost_set_vring_call = vhost_vfio_set_vring_call,
        .vhost_set_features = vhost_vfio_set_features,
        .vhost_get_features = vhost_vfio_get_features,
        .vhost_set_owner = vhost_vfio_set_owner,
        .vhost_reset_device = vhost_vfio_reset_device,
        .vhost_get_vq_index = vhost_vfio_get_vq_index,
        .vhost_set_vring_enable = vhost_vfio_set_vring_enable,
        .vhost_requires_shm_log = NULL,
        .vhost_migration_done = vhost_vfio_migration_done,
        .vhost_backend_can_merge = NULL,
        .vhost_net_set_mtu = NULL,
        .vhost_set_iotlb_callback = vhost_vdpa_set_iotlb_callback,
        .vhost_send_device_iotlb_msg = NULL,
        .vhost_set_state = vhost_vfio_set_state,
};
