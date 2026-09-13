#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <driver/types.h>
#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "comm.h"
#include "harvest.h"
#include "dirent_hide.h"
#include "hook_engine.h"
#include "hwbp.h"
#include "input_synth.h"
#include "kallsym.h"
#include "log.h"
#include "memory.h"
#include "sensor.h"
#include "stealth.h"
#include "user_hook.h"
#include "comm_wxshadow.h" /* 新增 WX 路由头 */

static long dispatch_ioctl_unlocked(struct file *filp, unsigned int cmd, unsigned long arg);

static long do_get_apga_keys(void __user *arg) {
	struct drv_ioctl_req req;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	u64 apga_lo = 0, apga_hi = 0;
	int rc;

	if (read_req(arg, &req) != 0) return -EFAULT;
	resolve_target_mm((pid_t)req.pid, &task, &mm);
	if (!task) return -ESRCH;
	rc = process_get_apga(task, &apga_lo, &apga_hi);
	release_target_mm(task, mm);
	if (rc) return rc;

	req.size = apga_lo;
	req.extra = apga_hi;
	if (copy_to_user(arg, &req, sizeof(req)) != 0) return -EFAULT;
	return 0;
}

static long do_find_pid_by_package(void __user *arg) {
	struct drv_find_pid_req req;
	size_t package_len;
	pid_t pid;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0) return -EFAULT;
	if (req.flags != 0) return -EINVAL;

	package_len = strnlen(req.package, sizeof(req.package));
	if (!package_len) return -EINVAL;
	if (package_len == sizeof(req.package)) return -ENAMETOOLONG;

	rc = process_find_pid_by_package(req.package, &pid);
	if (rc) return rc;

	req.pid = pid;
	if (copy_to_user(arg, &req, sizeof(req)) != 0) return -EFAULT;
	return 0;
}

static long do_hook_cmd(unsigned int cmd, void __user *arg) {
	switch (cmd) {
		case DRV_CMD_GAME_ASSET_READ_A:
			if (copy_to_user(arg, drv.wz_hero_addr_map, DRV_WZ_HERO_ADDR_MAP_BYTES) != 0)
				return -EFAULT;
			return 0;
		case DRV_CMD_INSTALL_HOOKS:
			return install_harvest_hooks();
		case DRV_CMD_TEAR_DOWN:
			wz_hero_addr_map_clear();
			memset(drv.wz_hero_objects, 0, sizeof(drv.wz_hero_objects));
			return 0;
		case DRV_CMD_GAME_ASSET_READ_B:
			if (copy_to_user(arg, drv.wz_hero_objects, DRV_WZ_HERO_OBJECTS_BYTES) != 0)
				return -EFAULT;
			return 0;
		case DRV_CMD_INSTALL_SIGSEGV_SUPPRESS:
			return install_harvest_hooks();
		default:
			return 0;
	}
}

static long do_input_cmd(unsigned int cmd, void __user *arg) {
	struct drv_touch_inject_req t;
	int ret;

	ret = install_input_hooks();
	if (ret) return ret;

	switch (cmd) {
		case DRV_CMD_TOUCH_DOWN:
			if (copy_from_user(&t, arg, sizeof(t)) != 0) return -EFAULT;
			touch_down((int)t.slot_id, (int)t.x, (int)t.y, (int)t.pressure);
			t.pressure = 1;
			(void)copy_to_user(arg, &t, sizeof(t));
			return 0;
		case DRV_CMD_TOUCH_UP:
			if (copy_from_user(&t, arg, sizeof(t)) != 0) return -EFAULT;
			touch_up((int)t.slot_id);
			return 0;
		case DRV_CMD_TOUCH_MOVE:
			if (copy_from_user(&t, arg, sizeof(t)) != 0) return -EFAULT;
			touch_move((int)t.slot_id, (int)t.x, (int)t.y);
			return 0;
		case DRV_CMD_TOUCH_SLOT_LEGACY:
			return 0;
		case DRV_CMD_SENSOR_BIND: {
			struct drv_ioctl_req req;
			if (read_req(arg, &req) != 0) return -EFAULT;
			if (req.pid == 100) {
				if (req.size >= DRV_SENSOR_LAYOUT_COUNT) return -EINVAL;
				return sensor_hook_init((unsigned long)req.addr, (int)req.size);
			}
			gyro_x = (u32)req.addr;
			gyro_y = (u32)req.size;
			gyro_enable = (u8)(req.extra != 0);
			return 0;
		}
		default:
			return 0;
	}
}

_Static_assert(DRV_CMD_HWBP_RANGE_LAST < DRV_CMD_PTE_HOOK_RANGE_FIRST, "HWBP primary range overlaps PTE_HOOK range");
_Static_assert(DRV_CMD_PTE_HOOK_RANGE_LAST < DRV_CMD_HWBP_EXT_RANGE_FIRST, "PTE_HOOK range overlaps HWBP extended range");
_Static_assert(DRV_CMD_HWBP_INSTALL != DRV_CMD_PTE_HOOK_INSTALL && DRV_CMD_HWBP_GET_HITS != DRV_CMD_PTE_HOOK_INSTALL, "HWBP command collides with PTE_HOOK_INSTALL");

static long dispatch_ioctl_unlocked(struct file *filp, unsigned int cmd, unsigned long arg) {
	void __user *uarg = (void __user *)arg;
	u64 hello;

	if (cmd == DRIVER_IOCTL_PING) return 0;

	if (cmd == DRIVER_IOCTL_HELLO) {
		hello = DRIVER_IOCTL_HELLO;
		if (copy_to_user(uarg, &hello, sizeof(hello)) != 0) return -EFAULT;
		return 0;
	}

	if (cmd == DRV_CMD_FIND_PID_BY_PACKAGE) return do_find_pid_by_package(uarg);
	if (cmd == DRV_CMD_GET_APGA_KEYS) return do_get_apga_keys(uarg);

	if (cmd >= DRV_CMD_READ_MEM_LINEAR && cmd <= DRV_CMD_DUMP_VMAS) return do_memory_cmd(cmd, uarg);
	if (cmd >= DRV_CMD_GAME_ASSET_READ_A && cmd <= DRV_CMD_INSTALL_SIGSEGV_SUPPRESS) return do_hook_cmd(cmd, uarg);
	if (cmd >= DRV_CMD_INPUT_RANGE_FIRST && cmd <= DRV_CMD_INPUT_RANGE_LAST) return do_input_cmd(cmd, uarg);
	if (cmd >= DRV_CMD_HWBP_RANGE_FIRST && cmd <= DRV_CMD_HWBP_RANGE_LAST) return do_hwbp_cmd(cmd, uarg, filp);
	if (cmd >= DRV_CMD_HWBP_EXT_RANGE_FIRST && cmd <= DRV_CMD_HWBP_EXT_RANGE_LAST) return do_hwbp_ext_cmd(cmd, uarg, filp);
	if (cmd >= DRV_CMD_PTE_HOOK_RANGE_FIRST && cmd <= DRV_CMD_PTE_HOOK_RANGE_LAST) return do_pte_hook_cmd(cmd, uarg);
	if (cmd >= DRV_CMD_HIDE_PID_RANGE_FIRST && cmd <= DRV_CMD_HIDE_PID_RANGE_LAST) return do_dirent_hide_cmd(cmd, uarg);

	/* 新增：W^X Shadow Hook 路由 */
	if (cmd >= DRV_CMD_WX_SET_BP && cmd <= DRV_CMD_WX_GET_STATE)
		return do_wxshadow_cmd(cmd, uarg, filp);

	return -ENOTTY;
}

long dispatch_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	return dispatch_ioctl_unlocked(filp, cmd, arg);
}
