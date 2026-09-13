// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_WX_COMPAT_H
#define DRV_WX_COMPAT_H

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/highmem.h>

/* ---- kmap_local_page / kunmap_local: landed in 5.11 ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#ifndef kmap_local_page
#define kmap_local_page(page) kmap(page)
#endif
#ifndef kunmap_local
#define kunmap_local(addr) kunmap(addr)
#endif
#endif

/* ---- get_user_pages_remote: 7 args (…pages, vmas, locked) until 6.5; 6 args after ----
 * This header is force-included (-include) before the TU body; the #include of
 * mm.h above lets the real prototype parse first, so the macro below only
 * rewrites 6-arg CALL sites. The self-reference in the replacement list is not
 * re-expanded, so it resolves to the real 7-arg function. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
#define get_user_pages_remote(mm, start, nr, gup_flags, pages, locked) \
	get_user_pages_remote((mm), (start), (nr), (gup_flags), (pages), NULL, (locked))
#endif

/* ---- vm_flags mutators: vm_flags_set/clear landed in 6.3 ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
#ifndef vm_flags_set
#define vm_flags_set(vma, flags) ((vma)->vm_flags |= (flags))
#endif
#ifndef vm_flags_clear
#define vm_flags_clear(vma, flags) ((vma)->vm_flags &= ~(flags))
#endif
#endif

#endif /* DRV_WX_COMPAT_H */
