// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>

#if KCFG_HIDE_SELF_MODULE
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/poison.h>
#endif

#if KCFG_HIDE_VMAP
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#endif

#include <asm/memory.h>
#include <asm/page.h>
#include <asm/sysreg.h>

#include <driver/types.h>

#include "comm.h"
#include "dirent_hide.h"
#include "hwbp.h"
#include "kallsym.h"
#include "lifecycle.h"
#include "log.h"
#include "memory.h"
#include "module_hide.h"
#include "stealth.h"

#include "wxshadow/wxshadow.h"
#include "inline_hook_frame.h"
#include "export_fun.h"

struct drv_state drv;

#if KCFG_HIDE_SELF_MODULE
#ifndef KCFG_DECOY_NAME
#define KCFG_DECOY_NAME "iptable_filter"
#endif

static void conceal_module(void) {
	struct module *mod = THIS_MODULE;
	const char decoy[] = KCFG_DECOY_NAME;
	size_t dlen = sizeof(decoy) - 1u;

	if (dlen >= sizeof(mod->name))
		dlen = sizeof(mod->name) - 1u;
	memset(mod->name, 0, sizeof(mod->name));
	memcpy(mod->name, decoy, dlen);

	list_del(&mod->list);
	INIT_LIST_HEAD(&mod->list);
	kobject_del(&mod->mkobj.kobj);
	list_del(&mod->mkobj.kobj.entry);

	mod->taints = 0;
#ifdef CONFIG_MODVERSIONS
	mod->version = NULL;
	mod->srcversion = NULL;
#endif
	mod->notes_attrs = NULL;
	mod->modinfo_attrs = NULL;
#ifdef CONFIG_STACKTRACE_BUILD_ID
	memset(mod->build_id, 0, sizeof(mod->build_id));
#endif
}
#endif

#if KCFG_HIDE_VMAP
struct drv_vmap_area_lite {
	unsigned long va_start;
	unsigned long va_end;
	struct rb_node rb_node;
	struct list_head list;
};

static void conceal_vmap(void) {
	struct list_head *vmap_list = (struct list_head *)kallsym_lookup("vmap_area_list");
	spinlock_t *vmap_lock = (spinlock_t *)kallsym_lookup("vmap_area_lock");
	struct rb_root *vmap_root = (struct rb_root *)kallsym_lookup("vmap_area_root");
	unsigned long probe = (unsigned long)(uintptr_t)&drv;
	struct drv_vmap_area_lite *va, *tmp;
	unsigned long flags = 0;
	int erased = 0;

	if (!vmap_list) {
		LOGW("conceal_vmap: vmap_area_list not resolvable, skip\n");
		return;
	}
	if (vmap_lock) spin_lock_irqsave(vmap_lock, flags);
	list_for_each_entry_safe(va, tmp, vmap_list, list) {
		if (probe < va->va_start || probe >= va->va_end) continue;
		list_del(&va->list);
		INIT_LIST_HEAD(&va->list);
		if (vmap_root) rb_erase(&va->rb_node, vmap_root);
		erased = 1;
		LOGI("conceal_vmap: unlinked va %lx..%lx (probe %lx)\n", va->va_start, va->va_end, probe);
		break;
	}
	if (vmap_lock) spin_unlock_irqrestore(vmap_lock, flags);
	if (!erased) LOGW("conceal_vmap: no vmap area contained probe %lx\n", probe);
}
#endif

static void mm_globals_init(void) {
	u64 tcr = read_sysreg(tcr_el1);
	u64 ttbr1 = read_sysreg(ttbr1_el1);
	u32 t1sz = (tcr >> 16) & 0x3Fu;
	u64 pgd_pa = ttbr1 & PHYS_MASK & PAGE_MASK;
	drv.m_page_level = (60u - t1sz) / 9u;
	drv.m_pgd_va = (u64)(uintptr_t)phys_to_virt(pgd_pa);
}

static int drv_on_do_exit(struct pt_regs *regs)
{
	struct task_struct *t = current;
	if (thread_group_leader(t))
		wxshadow_on_process_exit(t->mm);
	return 0;
}

static int drv_on_copy_process(struct pt_regs *regs)
{
	struct mm_struct *mm = current->mm;
	if (mm)
		wxshadow_on_fork_pause(mm);
	return 0;
}

int __init init_driver(void) {
	int ret;

	LOGI("driver_entry\n");

	mm_globals_init();

	ret = kallsym_init();
	if (ret < 0) { LOGE("kallsym_init failed: %d\n", ret); return ret; }

	(void)memory_init();

	ret = comm_warm_symbols();
	if (ret < 0) { LOGE("comm_warm_symbols failed: %d\n", ret); return ret; }

	if (hwbp_init()) LOGN("hwbp commands disabled\n");
	if (dirent_hide_init()) LOGN("dirent_hide commands disabled\n");
	if (kgsl_stealth_arm()) LOGN("kgsl proactive stealth disabled\n");

	ret = register_kprobe(&reboot_kp);
	if (ret < 0) { LOGE("register_kprobe (__arm64_sys_reboot) failed: %d\n", ret); return ret; }

#if KCFG_HIDE_SELF_MODULE
	if (module_hide_arm())
		LOGN("module_hide arm failed; conceal_module still runs\n");
	conceal_module();
#endif
#if KCFG_HIDE_VMAP
	conceal_vmap();
#endif

	wxshadow_init();

	/* 初始化本编译单元的 patch_text 函数指针，否则 inline_hook_install 必失败 */
	drv_hook_deps_init();

	{
		static struct hook_entry do_exit_hook[] = {
			HOOK_ENTRY("do_exit", drv_on_do_exit)
		};
		inline_hook_install(do_exit_hook);
	}
	{
		static struct hook_entry copy_process_hook[] = {
			HOOK_ENTRY("copy_process", drv_on_copy_process)
		};
		inline_hook_install(copy_process_hook);
	}

	return 0;
}

module_init(init_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Android kernel driver");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
