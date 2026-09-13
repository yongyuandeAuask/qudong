// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_WX_COMPAT_H
#define DRV_WX_COMPAT_H

#include <linux/version.h>
#include <linux/highmem.h>

/* kmap_local_page/kunmap_local landed in 5.11; map to kmap/kunmap on 5.10. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#ifndef kmap_local_page
#define kmap_local_page(page) kmap(page)
#endif
#ifndef kunmap_local
#define kunmap_local(addr) kunmap(addr)
#endif
#endif

#endif /* DRV_WX_COMPAT_H */
