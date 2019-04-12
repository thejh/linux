#define pr_fmt(fmt) "KHP: " fmt

#include <linux/kernel.h>
#include <linux/khp.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/uaccess.h>

unsigned long weak_pointer_region_shifted;

EXPORT_SYMBOL(__khp_decode_ptr);
