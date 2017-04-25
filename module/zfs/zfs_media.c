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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * This file contains the code to implement file range locking in
 * ZFS, although there isn't much specific to ZFS (all that comes to mind is
 * support for growing the blocksize).
 *
 * Interface
 * ---------
 * Defined in zfs_media.h but essentially:
 *	media = zfs_media_range(zp, off, len, mediatype);
 *
 * AVL tree
 * --------
 * An AVL tree is used to maintain the state of the existing ranges
 * that are locked for exclusive (writer) or shared (reader) use.
 * The starting range offset is used for searching and sorting the tree.
 *
 * Common case
 * -----------
 * The (hopefully) usual case is of no overlaps or contention for
 * locks. On entry to zfs_lock_range() a media_t is allocated; the tree
 * searched that finds no overlap, and *this* media_t is placed in the tree.
 *
 * Ovemediaaps/Reference counting/Proxy locks
 * ---------------------------------------
 * The avl code only allows one node at a particular offset. Also it's very
 * inefficient to search through all previous entries looking for overlaps
 * (because the very 1st in the ordered list might be at offset 0 but
 * cover the whole file).
 * So this implementation uses reference counts and proxy range locks.
 * Firstly, only reader locks use reference counts and proxy locks,
 * because writer locks are exclusive.
 * When a reader lock overlaps with another then a proxy lock is created
 * for that range and replaces the original lock. If the overlap
 * is exact then the reference count of the proxy is simply incremented.
 * Otherwise, the proxy lock is split into smaller lock ranges and
 * new proxy locks created for non overlapping ranges.
 * The reference counts are adjusted accordingly.
 * Meanwhile, the original lock is kept around (this is the callers handle)
 * and its offset and length are used when releasing the lock.
 *
 * Thread coordination
 * -------------------
 * In order to make wakeups efficient and to ensure multiple continuous
 * readers on a range don't starve a writer for the same range lock,
 * two condition variables are allocated in each media_t.
 * If a writer (or reader) can't get a range it initialises the writer
 * (or reader) cv; sets a flag saying there's a writer (or reader) waiting;
 * and waits on that cv. When a thread unlocks that range it wakes up all
 * writers then all readers before destroying the lock.
 *
 * Append mode writes
 * ------------------
 * Append mode writes need to lock a range at the end of a file.
 * The offset of the end of the file is determined under the
 * range locking mutex, and the lock type converted from RL_APPEND to
 * RL_WRITER and the range locked.
 *
 * Grow block handling
 * -------------------
 * ZFS supports multiple block sizes currently up to 128K. The smallest
 * block size is used for the file which is grown as needed. During this
 * growth all other writers and readers must be excluded.
 * So if the block size needs to be grown then the whole file is
 * exclusively locked, then later the caller will reduce the lock
 * range to just the range to be written using zfs_reduce_range.
 */

#include <sys/zfs_media.h>
#include <sys/dnode.h>
#include <sys/hetfs.h>
#include <sys/het.h>

int media_tree = 0;
/*
 * If this is an original (non-proxy) lock then replace it by
 * a proxy and return the proxy.
 */
static media_t *
zfs_media_range_proxify(avl_tree_t *tree, media_t *media)
{
	media_t *proxy;

	if (media->m_proxy)
		return (media); /* already a proxy */

	avl_remove(tree, media);

	/* create a proxy range lock */
	proxy = kmem_alloc(sizeof (media_t), KM_SLEEP);
	proxy->m_off = media->m_off;
	proxy->m_len = media->m_len;
	proxy->m_type = media->m_type;
	proxy->m_proxy = B_TRUE;
	avl_add(tree, proxy);

	return (proxy);
}

/*
 * Split the range lock at the supplied offset
 * returning the *front* proxy.
 */
static media_t *
zfs_media_range_split(avl_tree_t *tree, media_t *media, uint64_t off)
{
	media_t *front, *rear;

	ASSERT3U(media->m_len, >, 1);
	ASSERT3U(off, >, media->m_off);
	ASSERT3U(off, <, media->m_off + media->m_len);

	/* create the rear proxy range lock */
	rear = kmem_alloc(sizeof (media_t), KM_SLEEP);
	rear->m_off = off;
	rear->m_len = media->m_off + media->m_len - off;
	rear->m_type = media->m_type;
	rear->m_proxy = B_TRUE;

	front = zfs_media_range_proxify(tree, media);
	front->m_len = off - media->m_off;

	avl_insert_here(tree, rear, front, AVL_AFTER);
	return (front);
}

/*
 * Create and add a new proxy range lock for the supplied range.
 */
static void
zfs_media_range_new_proxy(avl_tree_t *tree, uint64_t off, uint64_t len, media_type_t type)
{
	media_t *media;

	ASSERT(len);
	media = kmem_alloc(sizeof (media_t), KM_SLEEP);
	media->m_off = off;
	media->m_len = len;
	media->m_type = type;
	media->m_proxy = B_TRUE;
	avl_add(tree, media);
}

static void
zfs_media_range_add_reader(avl_tree_t *tree, media_t *new, media_t *prev, avl_index_t where)
{
	media_t *next;
	uint64_t off = new->m_off;
	uint64_t len = new->m_len;
    media_type_t type = new->m_type;

	/*
	 * prev arrives either:
	 * - pointing to an entry at the same offset
	 * - pointing to the entry with the closest previous offset whose
	 *   range may overlap with the new range
	 * - null, if there were no ranges starting before the new one
	 */
	if (prev) {
		if (prev->m_off + prev->m_len <= off) {
			prev = NULL;
		} else if (prev->m_off != off) {
			/*
			 * convert to proxy if needed then
			 * split this entry and bump ref count
			 */
			prev = zfs_media_range_split(tree, prev, off);
			prev = AVL_NEXT(tree, prev); /* move to rear range */
		}
	}
	ASSERT((prev == NULL) || (prev->m_off == off));

	if (prev)
		next = prev;
	else
		next = (media_t *)avl_nearest(tree, where, AVL_AFTER);

	if (next == NULL || off + len <= next->m_off) {
		/* no overlaps, use the original new media_t in the tree */
		avl_insert(tree, new, where);
		return;
	}

	if (off < next->m_off) {
		/* Add a proxy for initial range before the overlap */
		zfs_media_range_new_proxy(tree, off, next->m_off - off, type);
	}

//	new->m_cnt = 0; /* will use proxies in tree */
	/*
	 * We now search forward through the ranges, until we go past the end
	 * of the new range. For each entry we make it a proxy if it
	 * isn't already, then bump its reference count. If there's any
	 * gaps between the ranges then we create a new proxy range.
	 */
	for (prev = NULL; next; prev = next, next = AVL_NEXT(tree, next)) {
		if (off + len <= next->m_off)
			break;
		if (prev && prev->m_off + prev->m_len < next->m_off) {
			/* there's a gap */
			ASSERT3U(next->m_off, >, prev->m_off + prev->m_len);
			zfs_media_range_new_proxy(tree, prev->m_off + prev->m_len,
			    next->m_off - (prev->m_off + prev->m_len), type);
		}
		if (off + len == next->m_off + next->m_len) {
			/* exact overlap with end */
			next = zfs_media_range_proxify(tree, next);
    			return;
		}
		if (off + len < next->m_off + next->m_len) {
			/* new range ends in the middle of this block */
			next = zfs_media_range_split(tree, next, off + len);
			return;
		}
		ASSERT3U(off + len, >, next->m_off + next->m_len);
		next = zfs_media_range_proxify(tree, next);
	}

	/* Add the remaining end range. */
	zfs_media_range_new_proxy(tree, prev->m_off + prev->m_len,
	    (off + len) - (prev->m_off + prev->m_len), type);
}

/*
 * Check if a reader lock can be grabbed, or wait and recheck until available.
 */
static void
zfs_media_range_reader(zfs_media_t *zmedia, media_t *new)
{
	avl_tree_t *tree = &zmedia->zm_avl;
	media_t *prev, *next;
	avl_index_t where;
	uint64_t off = new->m_off;
	uint64_t len = new->m_len;

	/*
	 * Look for any writer locks in the range.
	 */
	prev = avl_find(tree, new, &where);
    if (prev)
        return ;
	if (prev == NULL)
		prev = (media_t *)avl_nearest(tree, where, AVL_BEFORE);

    if (prev && (off < prev->m_off + prev->m_len)) {
        if (off + len < prev->m_off + prev->m_len)
            goto got_lock;
    }

    if (prev)
        next = AVL_NEXT(tree, prev);
    else
        next = (media_t *)avl_nearest(tree, where, AVL_AFTER);
    for (; next; next = AVL_NEXT(tree, next)) {
        if ((off + len <= next->m_off) || (off + len <= next->m_off + next->m_len))
            goto got_lock;
    }

got_lock:
	/*
	 * Add the read lock, which may involve splitting existing
	 * locks and bumping ref counts (m_cnt).
	 */
	zfs_media_range_add_reader(tree, new, prev, where);
}

/*
 * Lock a range (offset, length) as either shared (RL_READER)
 * or exclusive (RL_WRITER). Returns the range lock structure
 * for later unlocking or reduce range (if entire file
 * previously locked as RL_WRITER).
 */
media_t *
zfs_media_range(zfs_media_t *zmedia, uint64_t off, uint64_t len, media_type_t type)
{
	media_t *new, *node;

	ASSERT(type == NVRAM || type == METASLAB_ROTOR_VDEV_TYPE_SSD || type == METASLAB_ROTOR_VDEV_TYPE_HDD);

	new = kmem_alloc(sizeof (media_t), KM_SLEEP);
	new->m_zmedia = zmedia;
	new->m_off = off;
	if (len + off < off)	/* overflow */
		len = UINT64_MAX - off;
	new->m_len = len;
	new->m_type = type;
	new->m_proxy = B_FALSE;

	mutex_enter(&zmedia->zm_mutex);
	/*
	 * First check for the usual case of no locks
	 */
	if (avl_numnodes(&zmedia->zm_avl) == 0)
		avl_add(&zmedia->zm_avl, new);
	else
		zfs_media_range_reader(zmedia, new);
	mutex_exit(&zmedia->zm_mutex);
    if (media_tree) {
        for (node = avl_first(&zmedia->zm_avl); node != NULL; node = AVL_NEXT(&zmedia->zm_avl, node)) {
            printk(KERN_EMERG "start off:%lld end off %lld\n", node->m_off, node->m_off + node->m_len);
        }
    }
	return (new);
}

/*
 * AVL comparison function used to order range locks
 * Locks are ordered on the start offset of the range.
 */
int
zfs_media_range_compare(const void *arg1, const void *arg2)
{
	const media_t *media1 = (const media_t *)arg1;
	const media_t *media2 = (const media_t *)arg2;

	return (AVL_CMP(media1->m_off, media2->m_off));
}

#ifdef _KERNEL
EXPORT_SYMBOL(zfs_media_range);
EXPORT_SYMBOL(zfs_media_range_compare);
#endif


int
find_in(dnode_t *dn, medium_t *start, loff_t end, medium_t *where) {

    medium_t *intermediate, *loop;
    where = NULL;
    for (loop = start; loop != NULL;) {
        if (end > loop->m_start || end < loop->m_end) {
            where = loop;
            return 1;
        }
        if (end == loop->m_start ) {
            where = loop;
            return 0;
        }
        if (end == loop->m_end ) {
            where = loop;
            list_remove(&dn->media, loop);
            kfree(loop);
            return 2;
        }
        intermediate = loop;
        loop = list_next(&dn->media, intermediate);
        list_remove(&dn->media, intermediate);
        kfree(intermediate);
    }
    return 0;
}

/* Interval list of medium of part of file*/
medium_t *
zfs_media_add(dnode_t *dn, loff_t *ppos, size_t len, int rot)
{

    int ret;
    medium_t *new, *loop, *next, *del;
    loff_t end = *ppos + len;
    if (list_is_empty(&dn->media)) {
        new = kzalloc(sizeof(medium_t), GFP_KERNEL);
        if (new == NULL)
            return NULL;
        new->m_start = *ppos;
        new->m_end = *ppos + len;
        new->m_type = rot;
        list_insert_head(&dn->media, new);
        return new;
    }

    new = NULL;
    for (loop = list_head(&dn->media); loop != NULL; loop = list_next(&dn->media, loop)) {
        if (*ppos > loop->m_end)
            continue;
        if (*ppos == loop->m_end) {
            next = list_next(&dn->media, loop);
            if (loop->m_type == rot) {
                loop->m_end = end;
                if (next->m_start < end)
                    return loop;
                if (next->m_start == end) {
                    if (next->m_type == rot) {
                        loop->m_end = next->m_end;
                        list_remove(&dn->media, next);
                    }
                    return loop;
                }
                /* next->m_start > end */
                ret = find_in(dn, next, end, new);
                if (ret < 2) {
                    if (new->m_type == rot) {
                        loop->m_end = new->m_end;
                        list_remove(&dn->media, new);
                        return loop;
                    }
                    if (ret == 1) {
                        loop->m_end = end;
                        new->m_start = end;
                        return loop;
                    }
                }
            } /* Different media */
            continue; /* If different media go to next node maybe is same or not*/
        } /* *ppos == loop->m_end */

        /* *ppos < loop->m_end*/
        if (loop->m_type != rot) {
            if (end < loop->m_end) {
                new = kzalloc(sizeof(medium_t), GFP_KERNEL);
                if (new == NULL)
                    return NULL;
                new->m_start = *ppos;
                new->m_end = end;
                new->m_type = rot;
                list_insert_after(&dn->media, loop, new);
                del = kzalloc(sizeof(medium_t), GFP_KERNEL);
                if (new == NULL)
                    return NULL;
                del->m_start = end;
                del->m_end = loop->m_end;
                del->m_type = rot;
                list_insert_after(&dn->media, new, del);
                loop->m_end = *ppos;
                return del;
            }
            if (end == loop->m_end) {
                next = list_next(&dn->media, loop);
                if (next->m_type == rot) {
                    next->m_start = *ppos;
                    loop->m_end = *ppos;
                    return loop;
                }
                new = kzalloc(sizeof(medium_t), GFP_KERNEL);
                if (new == NULL)
                    return NULL;
                new->m_start = *ppos;
                new->m_end = end;
                new->m_type = rot;
                list_insert_before(&dn->media, next, new);
                loop->m_end = *ppos;
                return new;
            }
            /* end > loop->m_end */
            next = list_next(&dn->media, loop);
            ret = find_in(dn, next, end, new);
            if (ret < 2) {
                if (new->m_type == rot) {
                    loop->m_end = new->m_end;
                    list_remove(&dn->media, new);
                    return loop;
                }
                if (ret == 1) {
                    loop->m_end = end;
                    new->m_start = end;
                    return loop;
                }
            }
            loop->m_end = end;
            return loop;
        }
    } /*for loop*/

    return NULL;
}
