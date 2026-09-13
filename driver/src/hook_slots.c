// SPDX-License-Identifier: GPL-2.0
/* Single owner of the inline-hook trampoline slot array.
 * The upstream header emits this array via inline asm in every TU that
 * includes it, which collides under LTO (ld-temp.o duplicate symbol).
 * We strip that asm in CI and provide exactly one definition here,
 * placed in an executable .text subsection and pre-filled with NOPs. */
#include <linux/types.h>

#define TRAMP_SLOT_COUNT 32
#define TRAMP_WORDS 120
#define TRAMP_NOP 0xD503201Fu

uint32_t inline_hook_trampoline_slots[TRAMP_SLOT_COUNT * TRAMP_WORDS]
	__attribute__((section(".text.tramp_slots"), aligned(8)))
	= { [0 ... (TRAMP_SLOT_COUNT * TRAMP_WORDS - 1)] = TRAMP_NOP };
