// SPDX-License-Identifier: GPL-2.0
#ifndef DRV_EXPORT_FUN_H
#define DRV_EXPORT_FUN_H

#include <linux/types.h>
#include <linux/kernel.h>
#include "kallsym.h"

typedef int (*aarch64_insn_patch_text_fn)(void *addrs[], u32 insns[], int cnt);
static aarch64_insn_patch_text_fn fn_aarch64_insn_patch_text;

static inline int drv_hook_deps_init(void)
{
	if (!fn_aarch64_insn_patch_text)
		fn_aarch64_insn_patch_text =
			(aarch64_insn_patch_text_fn)kallsym_lookup("aarch64_insn_patch_text");
	return fn_aarch64_insn_patch_text ? 0 : -ENOENT;
}

static inline u64 generic_kallsyms_lookup_name(const char *name)
{
	return (u64)kallsym_lookup(name);
}

static inline void arm64_make_ldr_ret(u64 addr, u32 *out)
{
	out[0] = 0x58000050; /* ldr x16, #8 */
	out[1] = 0xD61F0200; /* br x16 */
	out[2] = (u32)(addr & 0xFFFFFFFFu);
	out[3] = (u32)(addr >> 32);
}

#endif /* DRV_EXPORT_FUN_H */
