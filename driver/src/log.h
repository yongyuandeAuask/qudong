// SPDX-License-Identifier: GPL-2.0
#ifndef DRIVER_LOG_H
#define DRIVER_LOG_H

#include <linux/kernel.h>
#include <linux/printk.h>

#ifndef DRV_LOG_TAG
#define DRV_LOG_TAG "[memory-driver]"
#endif

#define LOGE(fmt, ...) printk(KERN_ERR DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) printk(KERN_WARNING DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGW_RL(fmt, ...) printk_ratelimited(KERN_WARNING DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGN(fmt, ...) printk(KERN_NOTICE DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) printk(KERN_INFO DRV_LOG_TAG " " fmt, ##__VA_ARGS__)

#ifdef CONFIG_DRIVER_VERBOSE_DEBUG
#define LOGD(fmt, ...) printk(KERN_DEBUG DRV_LOG_TAG " " fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...) do { } while (0)
#endif

#ifdef KCFG_LOG_SILENT
#undef LOGE
#undef LOGW
#undef LOGW_RL
#undef LOGN
#undef LOGI
#undef LOGD
#define LOGE(...) do {} while (0)
#define LOGW(...) do {} while (0)
#define LOGW_RL(...) do {} while (0)
#define LOGN(...) do {} while (0)
#define LOGI(...) do {} while (0)
#define LOGD(...) do {} while (0)
#endif

#endif /* DRIVER_LOG_H */