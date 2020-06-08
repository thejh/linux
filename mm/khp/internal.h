/* end object index per allocation type (normal / fallback) */
#define KHP_END_PER_TYPE 0x40000000UL

extern atomic_long_t khp_stat_global_frees, khp_stat_local_frees;

u16 khp_depletion_cookie(struct khp_meta *meta);

static __always_inline u32 khp_meta_idx(struct khp_meta *meta)
{
	return meta - khp_region_start;
}

static __always_inline struct khp_meta *khp_meta_by_idx(u32 obj_idx)
{
	return khp_region_start + obj_idx;
}
