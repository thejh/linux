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


static unsigned long region_memory(struct khp_region *r)
{
	return (READ_ONCE(r->alloc_end) - r->start) * sizeof(struct khp_meta);
}

static ssize_t khp_stats_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	char text[1000];
	int len;

	len = snprintf(text, sizeof(text),
		       "frees global: %ld\nfrees local: %ld\n"
		       "orig meta memory: %lu kB\n"
		       "fallback meta memory: %lu kB\n",
		       atomic_long_read(&khp_stat_global_frees),
		       atomic_long_read(&khp_stat_local_frees),
		       region_memory(&khp_orig_region) / 1024,
		       region_memory(&khp_fallback_region) / 1024);
	return simple_read_from_buffer(buf, count, ppos, text, len);
}

static struct file_operations khp_stats_fops = {
	.read = khp_stats_read,
	.llseek = generic_file_llseek,
};


static void *khp_dump_start(struct seq_file *m, loff_t *pos)
{
	if (*pos == KHP_LIST_END ||
	    READ_ONCE(khp_orig_region.alloc_end) == khp_orig_region.start)
		return NULL;
	return khp_meta_by_idx(*pos);
}

static void khp_dump_stop(struct seq_file *m, void *v) {}

static void *khp_dump_next(struct seq_file *m, void *v, loff_t *pos)
{
	u32 idx = *pos;
	u32 end_orig_idx =
		READ_ONCE(khp_orig_region.alloc_end) - khp_orig_region.start;
	u32 end_fb_idx =
		READ_ONCE(khp_fallback_region.alloc_end) - khp_orig_region.start;

	idx++;
	if (idx == end_orig_idx)
		idx = KHP_END_PER_TYPE;
	if (idx == end_fb_idx) {
		*pos = KHP_LIST_END;
		return NULL;
	}
	*pos = idx;
	return khp_meta_by_idx(idx);
}

/*
 * Note that not all updates are necessarily atomic! So we might still see
 * inconsistent state.
 */
static struct khp_meta grab_meta_atomic(struct khp_meta *m)
{
	struct khp_meta copy;
	while (1) {
		copy.halves[0] = READ_ONCE(m->halves[0]);
		copy.halves[1] = READ_ONCE(m->halves[1]);
		if (cmpxchg_double(&m->halves[0], &m->halves[1],
				   copy.halves[0], copy.halves[1],
				   copy.halves[0], copy.halves[1]))
			return copy;
	}
}

static int khp_dump_show(struct seq_file *m, void *v)
{
	struct khp_meta *meta = v;
	struct khp_meta copy = grab_meta_atomic(meta);
	u16 dcookie = khp_depletion_cookie(meta);
	int remaining = 100 * (u16)(dcookie - copy.khp_cookie) / 0x10000;
	u8 type = copy.khp_extag & KHP_ETT_MASK;
	bool released;

	seq_printf(m, "0x%08x", khp_meta_idx(meta));
	if (meta >= khp_fallback_region.start) {
		seq_puts(m, "[F] ");
	} else {
		seq_puts(m, "[N] ");
	}

	seq_printf(m, "cookie=0x%04x dcookie=0x%04x remaining=%3d%% ",
		   copy.khp_cookie, dcookie, remaining);
	switch (type) {
	case KHP_ETT_QUEUED:
		released = (copy.khp_extag & KHP_EXTAG_RELEASED) != 0;
		seq_printf(m, "state=%s-%s seq=%u ptr=%px",
			   released ? "released" : "queued",
			   (copy.khp_extag&KHP_EXTAG_GLOBAL_QUEUE)?"global":"local",
			   copy.khp_extag & KHP_SEQ_MASK);
		break;
	case KHP_ETT_ALLOC:
	case KHP_ETT_ALLOC_FB:
		seq_printf(m, "state=allocated ptr=%px", copy.khp_raw_ptr);
		break;
	case KHP_ETT_FLOATING:
		seq_printf(m, "state=floating refcount=%hu", copy.lar.khp_refcount);
		break;
	}
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations khp_dump_ops = {
	.start = khp_dump_start,
	.stop  = khp_dump_stop,
	.next  = khp_dump_next,
	.show  = khp_dump_show
};

static int khp_dump_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &khp_dump_ops);
}

static struct file_operations khp_dump_fops = {
	.open = khp_dump_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static int parse_user_ulong(unsigned long *res, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	char buf[100];

	if (*ppos != 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';
	return kstrtoul(buf, 16, res);
}

static ssize_t khp_trigger_crash_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	unsigned long user_supplied_ptr;
	int ret;

	ret = parse_user_ulong(&user_supplied_ptr, buffer, count, ppos);
	if (ret)
		return ret;

	/* intentionally dereference user-supplied pointer and discard result */
	*(volatile char *)user_supplied_ptr;

	return 0;
}

static struct file_operations khp_trigger_crash_fops = {
	.write = khp_trigger_crash_write
};

static ssize_t khp_trigger_kernelds_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *ppos)
{
	unsigned long user_supplied_ptr;
	mm_segment_t old_fs;
	int ret;
	char dummy;

	ret = parse_user_ulong(&user_supplied_ptr, buffer, count, ppos);
	if (ret)
		return ret;

	/*
	 * intentionally load user-supplied pointer under KERNEL_DS and discard
	 * result
	 */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = get_user(dummy, (char __user *)user_supplied_ptr);
	set_fs(old_fs);

	return ret;
}

static struct file_operations khp_trigger_kernelds_fops = {
	.write = khp_trigger_kernelds_write
};

static void __init khp_debugfs_init(void)
{
	struct dentry *debugfs_dir = debugfs_create_dir("khp", NULL);
	debugfs_create_file_size("stats", 0400, debugfs_dir, NULL,
				 &khp_stats_fops, 0);
	debugfs_create_file("dump", 0400, debugfs_dir, NULL, &khp_dump_fops);
	debugfs_create_file("trigger-crash", 0200, debugfs_dir, NULL,
			    &khp_trigger_crash_fops);
	debugfs_create_file("trigger-kernelds", 0200, debugfs_dir, NULL,
			    &khp_trigger_kernelds_fops);
}
fs_initcall(khp_debugfs_init);
