// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Ruleset management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/bug.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "object.h"
#include "ruleset.h"

static struct landlock_ruleset *create_ruleset(void)
{
	struct landlock_ruleset *ruleset;

	ruleset = kzalloc(sizeof(*ruleset), GFP_KERNEL);
	if (!ruleset)
		return ERR_PTR(-ENOMEM);
	refcount_set(&ruleset->usage, 1);
	mutex_init(&ruleset->lock);
	atomic_set(&ruleset->nb_rules, 0);
	ruleset->root = RB_ROOT;
	return ruleset;
}

struct landlock_ruleset *landlock_create_ruleset(u64 fs_access_mask)
{
	struct landlock_ruleset *ruleset;

	/* Safely handles 32-bits conversion. */
	BUILD_BUG_ON(!__same_type(fs_access_mask, _LANDLOCK_ACCESS_FS_LAST));

	/* Checks content. */
	if ((fs_access_mask | _LANDLOCK_ACCESS_FS_MASK) !=
			_LANDLOCK_ACCESS_FS_MASK)
		return ERR_PTR(-EINVAL);
	/* Informs about useless ruleset. */
	if (!fs_access_mask)
		return ERR_PTR(-ENOMSG);
	ruleset = create_ruleset();
	if (!IS_ERR(ruleset))
		ruleset->fs_access_mask = fs_access_mask;
	return ruleset;
}

/*
 * The underlying kernel object must be held by the caller.
 */
static struct landlock_ruleset_elem *create_ruleset_elem(
		struct landlock_object *object)
{
	struct landlock_ruleset_elem *ruleset_elem;

	ruleset_elem = kzalloc(sizeof(*ruleset_elem), GFP_KERNEL);
	if (!ruleset_elem)
		return ERR_PTR(-ENOMEM);
	RB_CLEAR_NODE(&ruleset_elem->node);
	ruleset_elem->object = object;
	return ruleset_elem;
}

static struct landlock_rule *create_rule(struct landlock_access *access)
{
	struct landlock_rule *new_rule;

	if (WARN_ON_ONCE(!access))
		return ERR_PTR(-EFAULT);
	new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return ERR_PTR(-ENOMEM);
	refcount_set(&new_rule->usage, 1);
	new_rule->access = *access;
	return new_rule;
}

/*
 * An inserted rule can not be removed, only disabled (cf. struct
 * landlock_ruleset_elem).
 *
 * The underlying kernel object must be held by the caller.
 *
 * @rule: Allocated struct owned by this function. The caller must hold the
 * underlying kernel object (e.g., with a FD).
 */
int landlock_insert_ruleset_rule(struct landlock_ruleset *ruleset,
		struct landlock_object *object, struct landlock_access *access,
		struct landlock_rule *rule)
{
	struct rb_node **new;
	struct rb_node *parent = NULL;
	struct landlock_ruleset_elem *ruleset_elem;
	struct landlock_rule *new_rule;

	might_sleep();
	/* Accesses may be set when creating a new rule. */
	if (rule) {
		if (WARN_ON_ONCE(access))
			return -EINVAL;
	} else {
		if (WARN_ON_ONCE(!access))
			return -EFAULT;
	}

	lockdep_assert_held(&ruleset->lock);
	new = &(ruleset->root.rb_node);
	while (*new) {
		struct landlock_ruleset_elem *this = rb_entry(*new,
				struct landlock_ruleset_elem, node);
		uintptr_t this_object;
		struct landlock_rule *this_rule;
		struct landlock_access new_access;

		this_object = (uintptr_t)this->object;
		if (this_object != (uintptr_t)object) {
			parent = *new;
			if (this_object < (uintptr_t)object)
				new = &((*new)->rb_right);
			else
				new = &((*new)->rb_left);
			continue;
		}

		/* Do not increment ruleset->nb_rules. */
		this_rule = this->rule;

		if (refcount_read(&this_rule->usage) == 1) {
			if (rule) {
				/* merge rule: intersection of access rights */
				this_rule->access.self &= rule->access.self;
				this_rule->access.beneath &=
					rule->access.beneath;
			} else {
				/* extend rule: union of access rights */
				this_rule->access.self |= access->self;
				this_rule->access.beneath |= access->beneath;
			}
			return 0;
		}

		/*
		 * If this_rule is shared with another ruleset, then create a
		 * new object rule.
		 */
		if (rule) {
			/* Merging a rule means an intersection of access. */
			new_access.self = this_rule->access.self &
				rule->access.self;
			new_access.beneath = this_rule->access.beneath &
				rule->access.beneath;
		} else {
			/* Extending a rule means a union of access. */
			new_access.self = this_rule->access.self |
				access->self;
			new_access.beneath = this_rule->access.self |
				access->beneath;
		}
		new_rule = create_rule(&new_access);
		if (IS_ERR(new_rule))
			return PTR_ERR(new_rule);
		this->rule = new_rule;
		landlock_put_rule(object, this_rule);
		return 0;
	}

	/* There is no match for @object. */
	ruleset_elem = create_ruleset_elem(object);
	if (IS_ERR(ruleset_elem))
		return PTR_ERR(ruleset_elem);
	if (rule) {
		refcount_inc(&rule->usage);
		new_rule = rule;
	} else {
		new_rule = create_rule(access);
		if (IS_ERR(new_rule)) {
			kfree(ruleset_elem);
			return PTR_ERR(new_rule);
		}
	}
	ruleset_elem->rule = new_rule;

	rb_link_node(&ruleset_elem->node, parent, new);
	rb_insert_color(&ruleset_elem->node, &ruleset->root);
	atomic_inc(&ruleset->nb_rules);
	return 0;
}

static int merge_ruleset(struct landlock_ruleset *dst,
		struct landlock_ruleset *src)
{
	struct rb_node *node;
	int err = 0;
	u32 checked_mask;

	might_sleep();
	if (!src)
		return 0;
	if (WARN_ON_ONCE(!dst))
		return -EFAULT;
	if (WARN_ON_ONCE(!dst->hierarchy))
		return -EINVAL;

	mutex_lock(&dst->lock);
	mutex_lock_nested(&src->lock, 1);
	checked_mask = dst->fs_access_mask;
	dst->fs_access_mask |= src->fs_access_mask;
	for (node = rb_first(&src->root); node; node = rb_next(node)) {
		struct landlock_ruleset_elem *elem = rb_entry(node,
				struct landlock_ruleset_elem, node);

		err = landlock_insert_ruleset_rule(dst, elem->object, NULL,
						   elem->rule);
		if (err)
			goto out_unlock;
	}

out_unlock:
	mutex_unlock(&src->lock);
	mutex_unlock(&dst->lock);
	return err;
}

void landlock_get_ruleset(struct landlock_ruleset *ruleset)
{
	if (!ruleset)
		return;
	refcount_inc(&ruleset->usage);
}

static void put_hierarchy(struct landlock_hierarchy *hierarchy)
{
	struct landlock_hierarchy *parent;
	while (hierarchy && refcount_dec_and_test(&hierarchy->usage)) {
		parent = hierarchy->parent;
		kfree(hierarchy);
		hierarchy = hierarchy->parent;
	}
}

static void free_ruleset(struct landlock_ruleset *ruleset)
{
	struct landlock_ruleset_elem *freeme, *tmp;

	might_sleep();
	rbtree_postorder_for_each_entry_safe(freeme, tmp, &ruleset->root, node) {
		landlock_put_rule(freeme->object, freeme->rule);
		kfree(freeme);
	}
	put_hierarchy(ruleset->hierarchy);
	kfree(ruleset);
}

void landlock_put_ruleset(struct landlock_ruleset *ruleset)
{
	might_sleep();
	if (ruleset && refcount_dec_and_test(&ruleset->usage))
		free_ruleset(ruleset);
}

static void put_ruleset_work(struct work_struct *work)
{
	struct landlock_ruleset *ruleset;

	ruleset = container_of(work, struct landlock_ruleset, work_put);
	free_ruleset(ruleset);
}

void landlock_put_ruleset_enqueue(struct landlock_ruleset *ruleset)
{
	if (ruleset && refcount_dec_and_test(&ruleset->usage)) {
		INIT_WORK(&ruleset->work_put, put_ruleset_work);
		schedule_work(&ruleset->work_put);
	}
}

/*
 * Creates a new ruleset, merged of @parent and @ruleset, or return @parent if
 * @ruleset is empty.  If @parent is empty, return a duplicate of @ruleset.
 *
 * @parent: Must not be modified (i.e. locked or read-only).
 */
struct landlock_ruleset *landlock_merge_ruleset(
		struct landlock_ruleset *parent,
		struct landlock_ruleset *ruleset)
{
	struct landlock_ruleset *new_dom;
	int err;

	might_sleep();

	if (parent && WARN_ON_ONCE(!parent->hierarchy))
		return ERR_PTR(-EINVAL);
	if (!ruleset || atomic_read(&ruleset->nb_rules) == 0 ||
			parent == ruleset) {
		landlock_get_ruleset(parent);
		return parent;
	}

	new_dom = create_ruleset();
	if (IS_ERR(new_dom))
		return new_dom;
	new_dom->hierarchy = kzalloc(sizeof(*new_dom->hierarchy), GFP_KERNEL);
	if (!new_dom->hierarchy) {
		landlock_put_ruleset(new_dom);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&new_dom->hierarchy->usage, 1);

	if (parent) {
		new_dom->hierarchy->parent = parent->hierarchy;
		refcount_inc(&parent->hierarchy->usage);
		err = merge_ruleset(new_dom, parent);
		if (err) {
			landlock_put_ruleset(new_dom);
			return ERR_PTR(err);
		}
	}
	err = merge_ruleset(new_dom, ruleset);
	if (err) {
		landlock_put_ruleset(new_dom);
		return ERR_PTR(err);
	}
	return new_dom;
}

const struct landlock_access *landlock_find_access(
		const struct landlock_ruleset *ruleset,
		const struct landlock_object *object)
{
	struct rb_node *node;

	if (!rcu_read_lock_held())
		lockdep_assert_held(&ruleset->lock);
	if (!object)
		return NULL;
	node = ruleset->root.rb_node;
	while (node) {
		struct landlock_ruleset_elem *this = rb_entry(node,
				struct landlock_ruleset_elem, node);
		uintptr_t this_object =
			(uintptr_t)rcu_access_pointer(this->object);

		if (this_object == (uintptr_t)object)
			return &rcu_dereference(this->rule)->access;

		if (this_object < (uintptr_t)object)
			node = node->rb_right;
		else
			node = node->rb_left;
	}
	return NULL;
}
