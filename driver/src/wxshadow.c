// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/rculist.h>
#include <asm/esr.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/memory.h>

#include "wxshadow.h"
#include "kallsym.h"
#include "log.h"

#define WX_MAX_INSNS 8
#define WX_PATCH_BYTES (WX_MAX_INSNS * 4)

#ifndef PTE_ADDR_MASK
#define PTE_ADDR_MASK (((pteval_t)1 << (PAGE_SHIFT + 36)) - 1)
#endif

struct wx_entry {
	struct file *owner;
	struct mm_struct *mm;
	unsigned long va;
	struct page *clean;
	struct page *shadow;
	pteval_t orig_pte;
	struct list_head list;
};

static LIST_HEAD(wx_list);
static DEFINE_SPINLOCK(wx_lock);
static struct kprobe kp_wx_abort;
static bool wx_hook_armed = false;

#define ARM64_RET_X30 0xd65f03c0
#define ARM64_NOP 0xd503201f
#define ARM64_BTI_C 0xd50324df

static int is_bti(u32 insn) { return (insn & 0xffffff3f) == 0xd503241f; }

static int emit_mov_x(u32 *out, int reg, u64 val) {
	int count = 0;
	out[count++] = 0xd2800000 | (reg) | ((val & 0xffff) << 5);
	if (val >> 16) out[count++] = 0xf2a00000 | (reg) | (((val >> 16) & 0xffff) << 5);
	if (val >> 32) out[count++] = 0xf2c00000 | (reg) | (((val >> 32) & 0xffff) << 5);
	if (val >> 48) out[count++] = 0xf2e00000 | (reg) | (((val >> 48) & 0xffff) << 5);
	return count;
}

static int build_patch(u32 out[], const u32 original[], u32 kind, u64 value) {
	int count = 0;
	memcpy(out, original, WX_PATCH_BYTES);
	out[count++] = is_bti(original[0]) ? original[0] : ARM64_BTI_C;
	switch (kind) {
		case DRV_PTE_HOOK_CONST_U64: count += emit_mov_x(&out[count], 0, value); out[count++] = ARM64_RET_X30; break;
		case DRV_PTE_HOOK_CONST_FLOAT: count += emit_mov_x(&out[count], 1, (u32)value); out[count++] = 0x1e270020; out[count++] = ARM64_RET_X30; break;
		case DRV_PTE_HOOK_CONST_DOUBLE: count += emit_mov_x(&out[count], 1, value); out[count++] = 0x9e670020; out[count++] = ARM64_RET_X30; break;
		case DRV_PTE_HOOK_VOID_RET: out[count++] = ARM64_RET_X30; break;
		default: return -EOPNOTSUPP;
	}
	while (count < WX_MAX_INSNS) out[count++] = ARM64_NOP;
	return 0;
}

static void wx_flush_va(unsigned long va) {
	unsigned long addr = va >> 12;
	asm volatile("dsb ishst");
	asm volatile("tlbi vaae1is, %0" :: "r"(addr));
	asm volatile("dsb ish");
	asm volatile("isb");
}

static pte_t *wx_pte_lock(struct mm_struct *mm, unsigned long va, spinlock_t **ptl) {
	pgd_t *pgd = pgd_offset(mm, va);
	p4d_t *p4d = p4d_offset(pgd, va);
	pud_t *pud = pud_offset(p4d, va);
	pmd_t *pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_leaf(*pmd)) return NULL;
	return pte_offset_map_lock(mm, pmd, va, ptl);
}

static void hide_kprobe_struct(struct kprobe *kp) {
	struct hlist_head *table = (struct hlist_head *)kallsym_lookup("kprobe_table");
	unsigned int hash; struct kprobe *pos;
	if (!table || !kp || !kp->addr) return;
	hash = ((unsigned long)kp->addr >> 2) & ((1u << 10) - 1);
	rcu_read_lock();
	hlist_for_each_entry_rcu(pos, &table[hash], hlist) {
		if (pos == kp) { hlist_del_rcu(&pos->hlist); break; }
	}
	rcu_read_unlock();
}

static void wx_free_entry(struct wx_entry *e) {
	spinlock_t *ptl; pte_t *ptep;
	ptep = wx_pte_lock(e->mm, e->va, &ptl);
	if (ptep) {
		set_pte(ptep, __pte(0)); wx_flush_va(e->va);
		set_pte(ptep, __pte(e->orig_pte)); wx_flush_va(e->va);
		pte_unmap_unlock(ptep, ptl);
	}
	if (e->clean) __free_page(e->clean);
	if (e->shadow) __free_page(e->shadow);
	mmput(e->mm);
	kfree(e);
}

static int do_install(void __user *arg, struct file *filp) {
	struct drv_pte_hook_install_req req;
	struct task_struct *task; struct mm_struct *mm;
	struct wx_entry *e; spinlock_t *ptl; pte_t *ptep;
	pteval_t orig, new; u32 patch[WX_MAX_INSNS];
	unsigned long off, pfn; void *orig_kva;

	if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
	off = req.addr & ~PAGE_MASK;
	if (off + WX_PATCH_BYTES > PAGE_SIZE) return -EINVAL;

	rcu_read_lock();
	task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
	if (task) get_task_struct(task);
	rcu_read_unlock();
	if (!task) return -ESRCH;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) return -EINVAL;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) { mmput(mm); return -ENOMEM; }
	e->owner = filp; e->mm = mm; e->va = req.addr & PAGE_MASK;
	e->clean = alloc_page(GFP_KERNEL); e->shadow = alloc_page(GFP_KERNEL);
	if (!e->clean || !e->shadow) goto fail_nomem;

	ptep = wx_pte_lock(mm, e->va, &ptl);
	if (!ptep || !pte_present(*ptep)) { if (ptep) pte_unmap_unlock(ptep, ptl); goto fail_unsup; }
	orig = pte_val(*ptep);
	pte_unmap_unlock(ptep, ptl);
	e->orig_pte = orig;

	pfn = pte_pfn(__pte(orig));
	orig_kva = phys_to_virt(pfn << PAGE_SHIFT);
	memcpy(page_address(e->clean), orig_kva, PAGE_SIZE);
	memcpy(page_address(e->shadow), page_address(e->clean), PAGE_SIZE);

	if (build_patch(patch, (u32*)page_address(e->clean), req.kind, req.ret_value) != 0) goto fail_unsup;
	memcpy(page_address(e->shadow) + off, patch, WX_PATCH_BYTES);

	ptep = wx_pte_lock(mm, e->va, &ptl);
	if (!ptep || pte_val(*ptep) != orig) { if (ptep) pte_unmap_unlock(ptep, ptl); goto fail_unsup; }
	
	new = orig;
	new &= ~PTE_ADDR_MASK;
	new |= (pteval_t)page_to_pfn(e->shadow) << PAGE_SHIFT;
	new &= ~PTE_USER;
	new &= ~(PTE_WRITE | PTE_DBM);
	new &= ~PTE_UXN;

	set_pte(ptep, __pte(0)); wx_flush_va(e->va);
	set_pte(ptep, __pte(new)); wx_flush_va(e->va);
	pte_unmap_unlock(ptep, ptl);

	spin_lock(&wx_lock);
	list_add(&e->list, &wx_list);
	spin_unlock(&wx_lock);

	if (!wx_hook_armed) {
		if (register_kprobe(&kp_wx_abort) == 0) {
			hide_kprobe_struct(&kp_wx_abort);
			wx_hook_armed = true;
		}
	}
	return 0;
fail_unsup:
	if (e->clean) __free_page(e->clean); if (e->shadow) __free_page(e->shadow);
	kfree(e); mmput(mm); return -EOPNOTSUPP;
fail_nomem:
	if (e->clean) __free_page(e->clean); if (e->shadow) __free_page(e->shadow);
	kfree(e); mmput(mm); return -ENOMEM;
}

static int do_remove(void __user *arg, struct file *filp) {
	struct drv_pte_hook_install_req req;
	struct wx_entry *e, *tmp;
	if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;
	spin_lock(&wx_lock);
	list_for_each_entry_safe(e, tmp, &wx_list, list) {
		if (e->va == (req.addr & PAGE_MASK) && e->owner == filp) {
			list_del(&e->list); spin_unlock(&wx_lock); wx_free_entry(e); return 0;
		}
	}
	spin_unlock(&wx_lock); return -ENOENT;
}

long do_wxshadow_cmd(unsigned int cmd, void __user *arg, struct file *filp) {
	switch (cmd) {
		case DRV_CMD_PTE_HOOK_INSTALL: return do_install(arg, filp);
		case DRV_CMD_PTE_HOOK_REMOVE: return do_remove(arg, filp);
		case DRV_CMD_PTE_HOOK_CLEAR_ALL: wxshadow_clear_by_file(filp); return 0;
		default: return -ENOTTY;
	}
}

void wxshadow_clear_by_file(struct file *filp) {
	struct wx_entry *e, *tmp; LIST_HEAD(dead);
	spin_lock(&wx_lock);
	list_for_each_entry_safe(e, tmp, &wx_list, list) {
		if (e->owner == filp) { list_del(&e->list); list_add(&e->list, &dead); }
	}
	spin_unlock(&wx_lock);
	list_for_each_entry_safe(e, tmp, &dead, list) { list_del(&e->list); wx_free_entry(e); }
}

static int wx_abort_pre(struct kprobe *p, struct pt_regs *regs) {
	unsigned long far = regs->regs[0];
	unsigned int esr = (unsigned int)regs->regs[1];
	/* 致命修复：do_mem_abort(far, esr, regs) -> x2 才是真正的用户态 pt_regs */
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[2]; 
	unsigned int ec = ESR_ELx_EC(esr);
	unsigned long page, off; struct wx_entry *e; void *ckva;
	unsigned int srt, sas;

	if (ec != ESR_ELx_EC_DABT_LOW || (esr & ESR_ELx_WNR)) return 0;
	page = far & PAGE_MASK; off = far & ~PAGE_MASK;

	spin_lock(&wx_lock);
	list_for_each_entry(e, &wx_list, list) {
		if (e->va != page || e->mm != current->mm) continue;
		ckva = page_address(e->clean);
		srt = (esr >> 16) & 0x1F; sas = (esr >> 22) & 0x3;
		if (srt < 31) {
			unsigned long v = 0;
			switch (sas) {
				case 0: v = *(u8 *)(ckva + off); break;
				case 1: v = *(u16 *)(ckva + off); break;
				case 2: v = *(u32 *)(ckva + off); break;
				default: v = *(u64 *)(ckva + off); break;
			}
			user_regs->regs[srt] = v; 
		}
		spin_unlock(&wx_lock);
		user_regs->pc += 4; 
		return 1;
	}
	spin_unlock(&wx_lock);
	return 0;
}

static struct kprobe kp_wx_abort = { .symbol_name = "do_mem_abort", .pre_handler = wx_abort_pre };
