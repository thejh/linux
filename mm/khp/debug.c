#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/khp.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/khprot.h>

atomic_long_t khp_stat_global_frees, khp_stat_local_frees;

#ifdef CONFIG_KHP_DEBUG
__attribute__((preserve_most))
void __khp_mark_global_debug(void *encoded_ptr, struct khp_meta **metap)
{
	struct khp_meta *meta = *metap;
	unsigned int cpu;
	int old_cpu = -1;
	int old_cpu_mask_inv;
	int new_cpu;
	struct page *page;

	if (!trace_globalize_enabled())
		return;

	old_cpu_mask_inv = READ_ONCE(meta->lar.etac.khp_cpu_mask_inv);
	new_cpu = raw_smp_processor_id();
	page = virt_to_head_page(meta->khp_raw_ptr);
	BUG_ON(!PageSlab(page));

	if (old_cpu_mask_inv == 0)
		return;

	for_each_possible_cpu(cpu) {
		if (per_cpu(cpu_fixedhamming_id, cpu) == (u8)~old_cpu_mask_inv) {
			old_cpu = cpu;
			break;
		}
	}
	if (old_cpu == -1) {
		pr_warn("trying to reverse CPU mask inv=0x%02x, normal=0x%02x\n", old_cpu_mask_inv, (u8)~old_cpu_mask_inv);
		BUG();
	}

	trace_globalize(old_cpu, new_cpu, page->slab_cache);
}
#endif /* CONFIG_KHP_DEBUG */


static ssize_t khp_stats_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	char text[1000];
	int len;

	len = snprintf(text, sizeof(text),
		       "frees global: %ld\nfrees local: %ld\n",
		       atomic_long_read(&khp_stat_global_frees),
		       atomic_long_read(&khp_stat_local_frees));
	return simple_read_from_buffer(buf, count, ppos, text, len);
}

static struct file_operations khp_stats_fops = {
	.read = khp_stats_read,
	.llseek = generic_file_llseek,
};

static void __init khp_debugfs_init(void)
{
	struct dentry *debugfs_dir = debugfs_create_dir("khp", NULL);
	debugfs_create_file_size("stats", 0400, debugfs_dir, NULL,
				 &khp_stats_fops, 0);
}
fs_initcall(khp_debugfs_init);
