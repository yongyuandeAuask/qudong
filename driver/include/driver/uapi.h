// SPDX-License-Identifier: GPL-2.0
#ifndef _DRIVER_UAPI_H
#define _DRIVER_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <linux/types.h>
#include <sys/types.h>
#endif

#ifndef KCFG_REBOOT_MAGIC
#define KCFG_REBOOT_MAGIC 0x123456u
#endif

#define DRIVER_REBOOT_MAGIC1 KCFG_REBOOT_MAGIC
#define DRIVER_REBOOT_MAGIC2 KCFG_REBOOT_MAGIC
#define DRIVER_IOCTL_PING 0x9FBF1u
#define DRIVER_IOCTL_HELLO 0x1E240u
#define DRV_MEM_CMD_MAX_SIZE (16ULL << 20)

enum drv_sensor_layout {
	DRV_SENSOR_LAYOUT_HIDL_V1 = 0,
	DRV_SENSOR_LAYOUT_AIDL_V1 = 1,
	DRV_SENSOR_LAYOUT_COUNT,
};

enum drv_cmd {
	DRV_CMD_READ_MEM_LINEAR = 0x0B,
	DRV_CMD_WRITE_MEM_LINEAR = 0x0C,
	DRV_CMD_READ_MEM_VMAP = 0x0D,
	DRV_CMD_WRITE_MEM_VMAP = 0x0E,
	DRV_CMD_GET_MODULE_BASE = 0x0F,
	DRV_CMD_FIND_TASK_BY_COMM = 0x10,
	DRV_CMD_READ_VMA_COOKIE = 0x11,
	DRV_CMD_GET_TLS = 0x12,
	DRV_CMD_HIDE_KGSL = 0x13,
	DRV_CMD_MULTI_READ = 0x14,
	DRV_CMD_DUMP_VMAS = 0x15,
	DRV_CMD_FIND_PID_BY_PACKAGE = 0x16,
	DRV_CMD_GET_APGA_KEYS = 0x17,

	DRV_CMD_GAME_ASSET_READ_A = 0xD0,
	DRV_CMD_INSTALL_HOOKS = 0xD1,
	DRV_CMD_TEAR_DOWN = 0xD2,
	DRV_CMD_GAME_ASSET_READ_B = 0xD4,
	DRV_CMD_INSTALL_SIGSEGV_SUPPRESS = 0xD5,

	DRV_CMD_TOUCH_DOWN = 0x12D,
	DRV_CMD_TOUCH_UP = 0x12E,
	DRV_CMD_TOUCH_MOVE = 0x12F,
	DRV_CMD_TOUCH_SLOT_LEGACY = 0x136,
	DRV_CMD_SENSOR_BIND = 0x140,
	DRV_CMD_INPUT_RANGE_FIRST = 0x12D,
	DRV_CMD_INPUT_RANGE_LAST = 0x18F,

	DRV_CMD_HWBP_INSTALL = 0x40,
	DRV_CMD_HWBP_REMOVE = 0x41,
	DRV_CMD_HWBP_SET_OVERRIDE = 0x42,
	DRV_CMD_HWBP_GET_HITS_LEGACY = 0x43,
	DRV_CMD_HWBP_CLEAR_ALL = 0x44,
	DRV_CMD_HWBP_GET_CAPS = 0x45,
	DRV_CMD_HWBP_SET_SAMPLE = 0x46,
	DRV_CMD_HWBP_SET_CONDITION = 0x47,
	DRV_CMD_HWBP_RANGE_FIRST = DRV_CMD_HWBP_INSTALL,
	DRV_CMD_HWBP_RANGE_LAST = DRV_CMD_HWBP_SET_CONDITION,

	DRV_CMD_PTE_HOOK_INSTALL = 0x48,
	DRV_CMD_PTE_HOOK_REMOVE = 0x49,
	DRV_CMD_PTE_HOOK_CLEAR_ALL = 0x4A,
	DRV_CMD_PTE_HOOK_RANGE_FIRST = DRV_CMD_PTE_HOOK_INSTALL,
	DRV_CMD_PTE_HOOK_RANGE_LAST = DRV_CMD_PTE_HOOK_CLEAR_ALL,

	DRV_CMD_HWBP_SET_BYPASS_PID = 0x60,
	DRV_CMD_HWBP_SET_NOTIFY = 0x61,
	DRV_CMD_HWBP_TRANSLATE_BAIT = 0x62,
	DRV_CMD_HWBP_GET_HITS = 0x63,
	DRV_CMD_HWBP_EXT_RANGE_FIRST = DRV_CMD_HWBP_SET_BYPASS_PID,
	DRV_CMD_HWBP_EXT_RANGE_LAST = DRV_CMD_HWBP_GET_HITS,

	DRV_CMD_HIDE_PID_ADD = 0x50,
	DRV_CMD_HIDE_PID_REMOVE = 0x51,
	DRV_CMD_HIDE_PID_CLEAR = 0x52,
	DRV_CMD_HIDE_PID_LIST = 0x53,
	DRV_CMD_HIDE_NAME_ADD = 0x54,
	DRV_CMD_HIDE_NAME_REMOVE = 0x55,
	DRV_CMD_HIDE_NAME_CLEAR = 0x56,
	DRV_CMD_HIDE_PID_RANGE_FIRST = DRV_CMD_HIDE_PID_ADD,
	DRV_CMD_HIDE_PID_RANGE_LAST = DRV_CMD_HIDE_NAME_CLEAR,

	/* Reverse shared-page ring registration */
	DRV_CMD_RING_REGISTER = 0x79,

	/* W^X Shadow Hook commands */
	DRV_CMD_WX_SET_BP = 0x80,
	DRV_CMD_WX_DEL_BP = 0x81,
	DRV_CMD_WX_PATCH = 0x82,
	DRV_CMD_WX_RELEASE = 0x83,
	DRV_CMD_WX_GET_STATE = 0x84,
};

#define DRV_PACKAGE_NAME_MAX 255u
struct drv_find_pid_req {
	__s32 pid;
	__u32 flags;
	char package[DRV_PACKAGE_NAME_MAX + 1u];
};

struct drv_ioctl_req {
	__u64 pid;
	__u64 addr;
	__u64 buf;
	__u64 size;
	__u64 extra;
};

struct drv_multi_read_req {
	__u64 user_dst;
	__u64 src_va;
	__u64 len;
};

struct drv_touch_inject_req {
	__u32 slot_id;
	__u32 x;
	__u32 y;
	__u32 pressure;
};

struct drv_input_event {
	__u32 type;
	__u32 code;
	__s32 value;
};

/* Reverse ring header: page 0 of the registered region. */
struct drv_ring_header {
	__u32 capacity;
	__u32 event_size;
	__u32 head;
	__u32 tail;
	__u64 dropped;
	__u64 stale;
};

#define DRV_HWBP_TYPE_R 1u
#define DRV_HWBP_TYPE_W 2u
#define DRV_HWBP_TYPE_RW 3u
#define DRV_HWBP_TYPE_X 4u
#define DRV_HWBP_TYPE_EXECUTE DRV_HWBP_TYPE_X
#define DRV_HWBP_LEN_1 1u
#define DRV_HWBP_LEN_2 2u
#define DRV_HWBP_LEN_4 4u
#define DRV_HWBP_LEN_8 8u
#define DRV_HWBP_LEN_EXECUTE DRV_HWBP_LEN_4
#define DRV_HWBP_MAX_OVERRIDES 10u
#define DRV_HWBP_HIT_RING_SLOTS 32u

#define DRV_HWBP_FLAG_BAIT_GUARD (1u << 0)
#define DRV_HWBP_FLAG_NOTIFY (1u << 1)
#define DRV_HWBP_FLAG_CAPTURE_FP (1u << 2)
#define DRV_HWBP_FLAG_TIMING_BYPASS (1u << 3)

#define DRV_HWBP_COND_NONE 0u
#define DRV_HWBP_COND_EQ 1u
#define DRV_HWBP_COND_NE 2u
#define DRV_HWBP_COND_LT 3u
#define DRV_HWBP_COND_LE 4u
#define DRV_HWBP_COND_GT 5u
#define DRV_HWBP_COND_GE 6u

enum drv_hwbp_reg_kind {
	DRV_HWBP_REG_NONE = 0,
	DRV_HWBP_REG_X = 1,
	DRV_HWBP_REG_VLO = 2,
	DRV_HWBP_REG_VHI = 3,
	DRV_HWBP_REG_PC = 4,
};

struct drv_hwbp_reg_override {
	__u32 kind;
	__u32 index;
	__u64 value;
};

struct drv_hwbp_install_req {
	__s32 pid;
	__u32 bp_len;
	__u32 bp_type;
	__u32 override_count;
	__u64 addr;
	__u32 pass_through;
	__u32 flags;
	struct drv_hwbp_reg_override overrides[DRV_HWBP_MAX_OVERRIDES];
};

struct drv_hwbp_hit {
	__u64 timestamp_ns;
	__u64 pc;
	__u64 sp;
	__u64 pstate;
	__u64 x[31];
	__u64 q_lo[32];
	__u64 q_hi[32];
	__u32 fpsr;
	__u32 fpcr;
};

#define DRV_HWBP_ABI_GENERATION 2u
#define DRV_HWBP_ABI_GEN_SHIFT 24u
#define DRV_HWBP_ABI_GEN_MASK 0xFFu
#define DRV_HWBP_CAPS_FLAGS_MASK 0x00FFFFFFu

#define DRV_HWBP_CAPS_GEN(v) (((v) >> DRV_HWBP_ABI_GEN_SHIFT) & DRV_HWBP_ABI_GEN_MASK)
#define DRV_HWBP_CAPS_FLAGS(v) ((v) & DRV_HWBP_CAPS_FLAGS_MASK)

struct drv_hwbp_caps {
	__u32 num_brps;
	__u32 num_wrps;
	__u32 ring_slots;
	__u32 max_overrides;
	__u32 hit_bytes;
	__u32 install_req_bytes;
	__u32 flags_supported;
	__u32 fp_ready;
};

struct drv_hwbp_sample_req {
	__s32 pid;
	__u32 _pad;
	__u64 addr;
	__u32 every;
	__u32 _pad2;
};

struct drv_hwbp_condition_req {
	__s32 pid;
	__u32 cond_op;
	__u64 addr;
	__u32 cond_reg;
	__u32 _pad;
	__u64 cond_value;
};

struct drv_hwbp_bypass_req {
	__s32 pid;
	__u32 _pad;
	__u64 addr;
	__s32 bypass_pid;
	__u32 _pad2;
};

struct drv_hwbp_notify_req {
	__s32 pid;
	__s32 notify_pid;
	__u64 addr;
	__u32 signal_no;
	__u32 _pad;
};

struct drv_hwbp_bait_req {
	__s32 pid;
	__u32 _pad;
	__u64 addr;
	__u64 real_addr;
};

enum drv_pte_hook_kind {
	DRV_PTE_HOOK_CONST_U64 = 0,
	DRV_PTE_HOOK_TRAMPOLINE = 1,
	DRV_PTE_HOOK_CONST_FLOAT = 2,
	DRV_PTE_HOOK_CONST_DOUBLE = 3,
	DRV_PTE_HOOK_VOID_RET = 4,
	DRV_PTE_HOOK_CONST_INT = DRV_PTE_HOOK_CONST_U64,
};

struct drv_pte_hook_install_req {
	__s32 pid;
	__u32 kind;
	__u64 addr;
	__u64 ret_value;
	__u64 tramp_addr;
	__u64 replace_addr;
};

struct drv_wxshadow_req {
	__s32 pid;
	__u32 _pad;
	__u64 addr;
	__u64 buf;
};

#endif /* _DRIVER_UAPI_H */
