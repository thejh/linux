#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/khp.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include "internal.h"

atomic_long_t khp_stat_global_frees, khp_stat_local_frees;


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
