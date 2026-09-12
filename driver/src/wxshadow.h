// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_WXSHADOW_H
#define DRV_WXSHADOW_H

#include <linux/fs.h>
#include <linux/types.h>
#include <driver/uapi.h> /* 关键修复：引入 ioctl 命令与结构体定义 */

long do_wxshadow_cmd(unsigned int cmd, void __user *arg, struct file *filp);
void wxshadow_clear_by_file(struct file *filp);

#endif /* DRV_WXSHADOW_H */
