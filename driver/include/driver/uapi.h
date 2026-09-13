/* W^X Shadow Hook structures (from Dispa1r io_struct.h) */
#define WXSHADOW_MAX_REG_MODS 4
#define WXSHADOW_PATCH_DATA_MAX 256
#define WXSHADOW_MAX_BP_RESULTS 32

struct wxshadow_reg_mod_info {
    uint8_t reg_idx;
    bool enabled;
    uint64_t value;
};

struct wxshadow_bp_cfg {
    uint64_t addr;
    int nr_reg_mods;
    struct wxshadow_reg_mod_info reg_mods[WXSHADOW_MAX_REG_MODS];
};

struct wxshadow_patch_cfg {
    uint64_t addr;
    uint16_t offset;
    uint16_t len;
    uint8_t data[WXSHADOW_PATCH_DATA_MAX];
};

struct wxshadow_page_entry {
    uint64_t page_addr;
    uint32_t nr_bps;
    uint32_t nr_patches;
    int32_t state;
    int32_t refcount;
};

struct wxshadow_state_info {
    int32_t total_pages;
    int32_t total_bps;
    int32_t total_patches;
