
#ifndef HW_VIRTIO_VHOST_VFIO_H
#define HW_VIRTIO_VHOST_VFIO_H

#include "hw/virtio/virtio.h"

typedef struct VhostVFIONotifyCtx {
    int kick_fd;
    void *addr;
    MemoryRegion mr;
    void *data;
} VhostVFIONotifyCtx;

typedef struct VhostVFIO {
    uint64_t bar0_offset;
    uint64_t bar0_size;
    uint64_t bar1_offset;
    uint64_t bar1_size;
    int device_fd;
    int group_fd;
    int container_fd;
    uint64_t iommu_pgsizes;

    VhostVFIONotifyCtx notify[VIRTIO_QUEUE_MAX];
} VhostVFIO;

#endif
