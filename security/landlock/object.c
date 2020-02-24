// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Object and rule management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 *
 * Principles and constraints of the object and rule management:
 * - Do not leak memory.
 * - Try as much as possible to free a memory allocation as soon as it is
 *   unused.
 * - Do not use global lock.
 * - Do not charge processes other than the one requesting a Landlock
 *   operation.
 */

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "object.h"

struct landlock_object *landlock_create_object(
		const struct landlock_object_operations *ops,
		void *underlying_object)
{
	struct landlock_object *object;

	if (WARN_ON_ONCE(!underlying_object))
		return NULL;
	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;
	refcount_set(&object->usage, 1);
	spin_lock_init(&object->lock);
	object->ops = ops;
	object->underlying_object = underlying_object;
	return object;
}

/*
 * Putting an object is easy when the object is being terminated, but it is
 * much more tricky when the reason is that there is no more rule tied to this
 * object.  Indeed, new rules could be added at the same time.
 */
void landlock_put_object(struct landlock_object *object)
{
	might_sleep();

	if (!object)
		return;

	/*
	 * If the object's refcount can't drop to zero, we can just decrement
	 * the refcount without holding a lock. Otherwise, the decrement must
	 * happen under object->lock for synchronization with things like
	 * get_inode_object().
	 */
	if (!refcount_dec_and_lock(&object->usage, &object->lock))
		return;

	/*
	 * With object->lock initially held, remove the reference from
	 * @object->underlying_object to @object.
	 */
	object->ops->release(object);

	kfree_rcu(object, rcu_free);
}

void landlock_put_rule(struct landlock_object *object,
		struct landlock_rule *rule)
{
	if (!rule)
		return;
	WARN_ON_ONCE(!object);

	if (refcount_dec_and_test(&rule->usage)) {
		landlock_put_object(object);
		kfree_rcu(rule, rcu_free);
	}
}
