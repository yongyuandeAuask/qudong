// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_WXSHADOW_H
#define DRV_WXSHADOW_H

#include <linux/fs.h>
#include <linux/types.h>

/* 兼容原 user_hook 的 ioctl 路由，增加 filp 参数用于 fd 生命周期绑定 */
long do_wxshadow_cmd(unsigned int cmd, void __user *arg, struct file *filp);

/* 供 comm.c 的 inofile_release 调用，清理当前 fd 关联的影子页 */
void wxshadow_clear_by_file(struct file *filp);

#endif /* DRV_WXSHADOW_H */
