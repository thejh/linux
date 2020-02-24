/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Filesystem management and hooks
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_FS_H
#define _SECURITY_LANDLOCK_FS_H

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/rcupdate.h>

#include "ruleset.h"
#include "setup.h"

struct landlock_inode_security {
	/*
	 * All writes are protected by i_lock.
	 * Disassociating @object from the inode is additionally protected by
	 * @object->lock, from the time @object's refcount drops to zero to the
	 * time this pointer is nulled out.
	 */
	struct landlock_object __rcu *object;
};

static inline struct landlock_inode_security *inode_landlock(
		const struct inode *inode)
{
	return inode->i_security + landlock_blob_sizes.lbs_inode;
}

__init void landlock_add_hooks_fs(void);

int landlock_append_fs_rule(struct landlock_ruleset *ruleset,
		struct path *path, u64 actions);

#endif /* _SECURITY_LANDLOCK_FS_H */
