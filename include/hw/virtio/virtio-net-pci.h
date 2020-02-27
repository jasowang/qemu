#include "qemu/osdep.h"

#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-net.h"
#include "virtio-pci.h"
#include "qapi/error.h"
#include "qemu/module.h"

typedef struct VirtIONetPCI VirtIONetPCI;

/*
 * virtio-net-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_NET_PCI "virtio-net-pci-base"
#define VIRTIO_NET_PCI(obj) \
        OBJECT_CHECK(VirtIONetPCI, (obj), TYPE_VIRTIO_NET_PCI)

struct VirtIONetPCI {
    VirtIOPCIProxy parent_obj;
    VirtIONet vdev;
};
/*
static inline VirtIOPCIProxy *virtio_device_to_virtio_pci_proxy(VirtIODevice *vdev)
{
    VirtIOPCIProxy *proxy = NULL;

    if (vdev->device_id == VIRTIO_ID_NET) {
        VirtIONetPCI *d = container_of(vdev, VirtIONetPCI, vdev.parent_obj);
        proxy = &d->parent_obj;
    }

    return proxy;
}*/
