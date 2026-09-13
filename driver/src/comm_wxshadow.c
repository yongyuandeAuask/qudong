// SPDX-License-Identifier: GPL-2.0
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <driver/uapi.h>
#include "wxshadow/wxshadow.h"
#include "wxshadow/io_struct.h"
#include "comm_wxshadow.h"

#define WX_MAX_INSNS 8

static int emit_mov_x(u32 *out, int reg, u64 val) {
	int count = 0;
	out[count++] = 0xd2800000 | (reg) | ((val & 0xffff) << 5);
	if (val >> 16) out[count++] = 0xf2a00000 | (reg) | (((val >> 16) & 0xffff) << 5);
	if (val >> 32) out[count++] = 0xf2c00000 | (reg) | (((val >> 32) & 0xffff) << 5);
	if (val >> 48) out[count++] = 0xf2e00000 | (reg) | (((val >> 48) & 0xffff) << 5);
	return count;
}

static int build_stub(u8 *bytes, u32 kind, u64 value) {
	u32 ins[WX_MAX_INSNS];
	int count = 0, i;

	ins[count++] = 0xd50324df; /* bti c */
	switch (kind) {
	case DRV_PTE_HOOK_CONST_U64:
		count += emit_mov_x(&ins[count], 0, value);
		ins[count++] = 0xd65f03c0; break;
	case DRV_PTE_HOOK_CONST_FLOAT:
		count += emit_mov_x(&ins[count], 1, (u32)value);
		ins[count++] = 0x1e270020;
		ins[count++] = 0xd65f03c0; break;
	case DRV_PTE_HOOK_CONST_DOUBLE:
		count += emit_mov_x(&ins[count], 1, value);
		ins[count++] = 0x9e670020;
		ins[count++] = 0xd65f03c0; break;
	case DRV_PTE_HOOK_VOID_RET:
		ins[count++] = 0xd65f03c0; break;
	default:
		return -EOPNOTSUPP;
	}
	while (count < WX_MAX_INSNS) ins[count++] = 0xd503201f;
	memcpy(bytes, ins, WX_MAX_INSNS * 4);
	return 0;
}

long do_pte_hook_cmd(unsigned int cmd, void __user *arg) {
	struct drv_pte_hook_install_req req;
	struct wxshadow_patch_cfg cfg;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;

	switch (cmd) {
	case DRV_CMD_PTE_HOOK_INSTALL:
		memset(&cfg, 0, sizeof(cfg));
		cfg.addr = req.addr & PAGE_MASK;
		cfg.offset = (u16)(req.addr & ~PAGE_MASK);
		if (build_stub(cfg.data, req.kind, req.ret_value) != 0)
			return -EOPNOTSUPP;
		cfg.len = (u16)(WX_MAX_INSNS * 4);
		return wxshadow_handle_patch(req.pid, cfg.addr, &cfg);
	case DRV_CMD_PTE_HOOK_REMOVE:
		return wxshadow_handle_release(req.pid, req.addr);
	case DRV_CMD_PTE_HOOK_CLEAR_ALL:
		return 0;
	default:
		return -ENOTTY;
	}
}

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
