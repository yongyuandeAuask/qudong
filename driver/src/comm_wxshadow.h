// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_COMM_WXSHADOW_H
#define DRV_COMM_WXSHADOW_H

#include <linux/fs.h>
#include <linux/types.h>

long do_wxshadow_cmd(unsigned int cmd, void __user *arg, struct file *filp);

#endif /* DRV_COMM_WXSHADOW_H */
