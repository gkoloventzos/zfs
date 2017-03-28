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

#ifndef	_SYS_FS_ZFS_MEDIA_H
#define	_SYS_FS_ZFS_MEDIA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>
#include <sys/avl.h>

#ifdef _KERNEL
#include <sys/condvar.h>
#else
#include <sys/zfs_context.h>
#endif

typedef enum {
	NVRAM,
	SSD,
	HDD
} media_type_t;

typedef struct zfs_media {
	kmutex_t zm_mutex;	/* protects changes to zm_avl */
	avl_tree_t zm_avl;	/* avl tree of range locks */
	uint64_t *zm_size;	/* points to znode->z_size */
	uint_t *zm_blksz;	/* points to znode->z_blksz */
    uint64_t *zm_max_blksz; /* points to zsb->z_max_blksz */
} zfs_media_t;

typedef struct media {
	zfs_media_t *m_zmedia;
	avl_node_t m_node;	/* avl node link */
	uint64_t m_off;		/* file range offset */
	uint64_t m_len;		/* file range length */
//	uint_t m_cnt;		/* range reference count in tree */
	media_type_t m_type;	/* range type */
//	kcondvam_t m_wm_cv;	/* cv for waiting writers */
//	kcondvam_t m_rd_cv;	/* cv for waiting readers */
	uint8_t m_proxy;	/* acting for original range */
//	uint8_t m_write_wanted;	/* writer wants to lock this range */
//	uint8_t m_read_wanted;	/* reader wants to lock this range */
	list_node_t media_node;	/* used for deferred release */
} media_t;

/*
 * Lock a range (offset, length) as either shared (RL_READER)
 * or exclusive (RL_WRITER or RL_APPEND).  RL_APPEND is a special type that
 * is converted to RL_WRITER that specified to lock from the start of the
 * end of file.  Returns the range lock structure.
 */
media_t *zfs_media_range(zfs_media_t *zmedia, uint64_t off, uint64_t len,
    media_type_t type);

/* Unlock range and destroy range lock structure. */
//void zfs_media_range_unlock(media_t *media);

/*
 * Reduce range locked as RW_WRITER from whole file to specified range.
 * Asserts the whole file was previously locked.
 */
//void zfs_media_range_reduce(media_t *media, uint64_t off, uint64_t len);

/*
 * AVL comparison function used to order range locks
 * Locks are ordered on the start offset of the range.
 */
int zfs_media_range_compare(const void *arg1, const void *arg2);

static inline void
zfs_media_init(zfs_media_t *zmedia)
{
	mutex_init(&zmedia->zm_mutex, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&zmedia->zm_avl, zfs_media_range_compare,
	    sizeof (media_t), offsetof(media_t, m_node));
	zmedia->zm_size = NULL;
	zmedia->zm_blksz = NULL;
	zmedia->zm_max_blksz = NULL;
}

static inline void
zfs_media_destroy(zfs_media_t *zmedia)
{
	avl_destroy(&zmedia->zm_avl);
	mutex_destroy(&zmedia->zm_mutex);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_MEDIA_H */
