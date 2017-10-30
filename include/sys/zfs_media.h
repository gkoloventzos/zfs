/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ZFS_MEDIA_H
#define	_SYS_ZFS_MEDIA_H

#include <linux/list.h>

#define	myoffsetof(s, m)	((size_t)(&(((s *)0)->m)))

typedef struct medium {
    loff_t m_start;
    loff_t m_end;
    int8_t m_type;
    struct list_head list;
} medium_t;

medium_t * zfs_media_add(struct list_head *dn, loff_t ppos, size_t len, int8_t rot);

#endif	/* _SYS_ZFS_MEDIA_H */
