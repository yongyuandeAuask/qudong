#include "comm.h"
#include "dirent_hide.h"
#include "hwbp.h"
#include "kallsym.h"
#include "lifecycle.h"
#include "log.h"
#include "memory.h"
#include "module_hide.h"
#include "stealth.h"
#include "user_hook.h"

/* 新增：引入模版 wxshadow 和 inline hook 框架 */
#include "wxshadow/wxshadow.h"
#include "inline_hook_frame.h"
#include "export_fun.h"

/* do_exit 清理：进程退出时清理所有 shadow 页 */
static int drv_on_do_exit(struct pt_regs *regs)
{
	struct task_struct *t = current;
	if (thread_group_leader(t))
		wxshadow_on_process_exit(t->mm);
	return 0;
}

/* copy_process fork 保护：子进程不继承 shadow PFN */
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
	if (user_hook_init()) LOGN("pte-hook commands disabled\n");
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

	/* 新增：W^X Shadow Hook 初始化 */
	wxshadow_init();

	/* 新增：do_exit 清理 hook */
	{
		static struct hook_entry do_exit_hook[] = {
			HOOK_ENTRY("do_exit", drv_on_do_exit)
		};
		inline_hook_install(do_exit_hook);
	}

	/* 新增：copy_process fork 保护 hook */
	{
		static struct hook_entry copy_process_hook[] = {
			HOOK_ENTRY("copy_process", drv_on_copy_process)
		};
		inline_hook_install(copy_process_hook);
	}

	return 0;
}
