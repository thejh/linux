/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Object and rule management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_OBJECT_H
#define _SECURITY_LANDLOCK_OBJECT_H

#include <linux/compiler_types.h>
#include <linux/list.h>
#include <linux/poison.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>

struct landlock_access {
	/*
	 * @self: Bitfield of allowed actions on the kernel object.  They are
	 * relative to the object type (e.g. LANDLOCK_ACTION_FS_READ).
	 */
	u32 self;
	/*
	 * @beneath: Same as @self, but for the child objects (e.g. a file in a
	 * directory).
	 */
	u32 beneath;
};

struct landlock_rule {
	struct landlock_access access;
	union {
		/*
		 * @usage: Number of rulesets pointing to this rule.  This
		 * field is never used by RCU readers.
		 */
		refcount_t usage;
		struct rcu_head rcu_free;
	};
};

enum landlock_object_type {
	LANDLOCK_OBJECT_INODE = 1,
};

struct landlock_object {
	/*
	 * @usage: Main usage counter, used to tie an object to it's underlying
	 * object (i.e. create a lifetime) and potentially add new rules.
	 * When potentially dropping this to zero, you must hold @lock.
	 */
	refcount_t usage;

	/*
	 * Protected by ->lock.
	 */
	void *underlying_object;

	const struct landlock_object_operations *ops;

	/*
	 * This lock must be from the time @usage drops to zero until any weak
	 * references from @underlying_object to this object have been cleaned
	 * up.
	 *
	 * Lock ordering:
	 *  - inode->i_lock nests inside this
	 */
	spinlock_t lock;

	struct rcu_head rcu_free;
};

struct landlock_object_operations {
	void (*release)(struct landlock_object *object)
		__releases(object->lock);
};

void landlock_put_rule(struct landlock_object *object,
		struct landlock_rule *rule);

struct landlock_object *landlock_create_object(
		const struct landlock_object_operations *ops,
		void *underlying_object);

void landlock_put_object(struct landlock_object *object);

#endif /* _SECURITY_LANDLOCK_OBJECT_H */
