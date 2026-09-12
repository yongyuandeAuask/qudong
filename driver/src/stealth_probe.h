// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_STEALTH_PROBE_H
#define DRV_STEALTH_PROBE_H

#include <linux/kprobes.h>

int stealth_probe_init(void);
void stealth_hide_kprobe(struct kprobe *kp);

#endif /* DRV_STEALTH_PROBE_H */
