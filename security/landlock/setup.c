// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Security framework setup
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/init.h>
#include <linux/lsm_hooks.h>

#include "cred.h"
#include "fs.h"
#include "ptrace.h"
#include "setup.h"

bool landlock_initialized __lsm_ro_after_init = false;

struct lsm_blob_sizes landlock_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct landlock_cred_security),
	.lbs_inode = sizeof(struct landlock_inode_security),
};

static int __init landlock_init(void)
{
	pr_info(LANDLOCK_NAME ": Registering hooks\n");
	landlock_add_hooks_cred();
	landlock_add_hooks_ptrace();
	landlock_add_hooks_fs();
	landlock_initialized = true;
	return 0;
}

DEFINE_LSM(LANDLOCK_NAME) = {
	.name = LANDLOCK_NAME,
	.init = landlock_init,
	.blobs = &landlock_blob_sizes,
};
