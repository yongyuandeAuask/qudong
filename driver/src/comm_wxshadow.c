// SPDX-License-Identifier: GPL-2.0
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <driver/uapi.h>
#include "wxshadow/wxshadow.h"
#include "wxshadow/io_struct.h"
#include "comm_wxshadow.h"

long do_wxshadow_cmd(unsigned int cmd, void __user *arg, struct file *filp)
{
	struct drv_wxshadow_req req;
	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;

	switch (cmd) {
	case DRV_CMD_WX_SET_BP:
		return wxshadow_handle_set_bp(req.pid, req.addr,
			(const struct wxshadow_bp_cfg *)(uintptr_t)req.buf);
	case DRV_CMD_WX_DEL_BP:
		return wxshadow_handle_del_bp(req.pid, req.addr);
	case DRV_CMD_WX_PATCH:
		return wxshadow_handle_patch(req.pid, req.addr,
			(const struct wxshadow_patch_cfg *)(uintptr_t)req.buf);
	case DRV_CMD_WX_RELEASE:
		return wxshadow_handle_release(req.pid, req.addr);
	case DRV_CMD_WX_GET_STATE:
		return wxshadow_handle_get_state(req.pid,
			(struct wxshadow_state_info *)(uintptr_t)req.buf);
	default:
		return -ENOTTY;
	}
}
