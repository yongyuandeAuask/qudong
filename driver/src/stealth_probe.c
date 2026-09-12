// SPDX-License-Identifier: GPL-2.0
#include <linux/kprobes.h>
#include <linux/rculist.h>
#include "kallsym.h"
#include "stealth_probe.h"

static struct hlist_head *s_table;

int stealth_probe_init(void) {
	s_table = (struct hlist_head *)kallsym_lookup("kprobe_table");
	return s_table ? 0 : -ENOENT;
}

/* 从 kprobe_table 哈希表中物理摘除探针结构体。
 * 注意：摘除后禁止调用 unregister_kprobe，否则会双重 hlist_del 导致内核 Panic。
 * 本驱动无卸载路径（重启前不替换），满足此约束。
 */
void stealth_hide_kprobe(struct kprobe *kp) {
	unsigned int hash;
	struct kprobe *pos;

	if (!s_table || !kp || !kp->addr) return;
	
	/* 5.10..6.12 KPROBE_HASH_BITS 默认为 10 */
	hash = ((unsigned long)kp->addr >> 2) & ((1u << 10) - 1);
	
	rcu_read_lock();
	hlist_for_each_entry_rcu(pos, &s_table[hash], hlist) {
		if (pos == kp) {
			hlist_del_rcu(&pos->hlist);
			break;
		}
	}
	rcu_read_unlock();
}
