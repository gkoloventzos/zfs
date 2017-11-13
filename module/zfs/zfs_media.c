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
 */

#include <sys/zfs_media.h>
#include <linux/slab.h>

medium_t *
find_in(struct list_head *head, medium_t *start, bool contin, loff_t posi, int *ret) {

    medium_t *where, *n, *pos;
    where = NULL;
    if (start == NULL)
        return NULL;
    if (contin)
        pos = list_next_entry(start, list);
    else
        pos = list_first_entry(head, typeof(*where), list);
    n = list_next_entry(pos, list);
    do {        
        where = pos;
        if (posi > pos->m_end) {
            pos = n;
            n = list_next_entry(n, list);
            continue;
        }
        if (posi < pos->m_start) {
            *ret = 0;
            return where;
        }
        if (posi == pos->m_end) {
            *ret = 1;
            return where;
        }
        if (posi == pos->m_start) {
            *ret = 2;
            return where;
        }
        *ret = 3;
        return where;
    } while (&pos->list != (head));
    return NULL;
}

/* Interval list of medium of part of file */
/* Debug of this will be done as we do experiments */
medium_t *
zfs_media_add(struct list_head *dn, loff_t ppos, size_t len, int8_t rot)
{

    int start, stop;
    medium_t *new, *loop, *next, *del;
    loff_t end = ppos + len;
    loop = new = del = NULL;
    start = stop = -1;

    if (list_empty(dn)) {
        new = kzalloc(sizeof(medium_t), GFP_KERNEL);
        if (new == NULL)
            return NULL;
        new->m_start = ppos;
        new->m_end = end;
        new->m_type = rot;
        list_add_tail(&new->list, dn);
        printk(KERN_EMERG "[LIST_ROT]zfs_media_add added at empty list\n");
        return new;
    }
    return NULL;
    printk(KERN_EMERG "[LIST_ROT]find first\n");
    loop = find_in(dn, list_first_entry(dn, typeof(*new), list), false, ppos, &start);

    new = kzalloc(sizeof(medium_t), GFP_KERNEL);
    if (new == NULL)
        return NULL;
    new->m_start = ppos;
    new->m_end = end;
    new->m_type = rot;

    if (loop == NULL) {
        list_add_tail(dn, &new->list);
        return new;
    }

    printk(KERN_EMERG "[LIST_ROT]find second\n");
    del = find_in(dn, loop, true, end, &stop);
    printk(KERN_EMERG "[LIST_ROT]find both\n");

    if (loop == del && loop != NULL) {
        if (start != 0 && stop != 0) {
            if (loop->m_type != rot) {
                list_add(&new->list, &loop->list);
                del = kzalloc(sizeof(medium_t), GFP_KERNEL);
                if (del == NULL)
                    return NULL;
                del->m_start = end;
                del->m_end = loop->m_end;
                del->m_type = loop->m_type;
                loop->m_end = ppos;
                list_add(&new->list, &del->list);
                return new;
            }
            else {
                kzfree(new);
                return loop;
            }
        }
    }

    switch(start) {
        case 0:
            list_add_tail(&new->list, &loop->list);
            next = loop;
            break;
        case 1:
            if (loop->m_type == rot) {
                new->m_start = loop->m_start;
                list_add_tail(&new->list, &loop->list);
                next = loop;
            }
            else {
                list_add(&new->list, &loop->list);
                next = list_next_entry(new, list);
            }
            break;
        case 2:
            list_add_tail(&new->list, &loop->list);
            next = loop;
            break;
        case 3:
            if (loop->m_type == rot) {
                loop->m_end = end;
                kzfree(new);
                new = loop;
                next = list_next_entry(new, list);
            }
            else {
                loop->m_end = new->m_start;
                list_add(&new->list, &loop->list);
                next = list_next_entry(new, list);
            }
            break;
        default:
            return NULL;
    }
    while (next != del) {
        loop = list_next_entry(next, list);
        list_del(&next->list);
        kzfree(next);
        next = loop;
    }
    switch (stop) {
        case 0:
            break;
        case 1:
            loop = list_next_entry(del, list);
            if (loop == NULL) {
                list_del(&del->list);
                kzfree(del);
                break;
            }
            if (end < loop->m_start) {
                return new;
            }
            /*only == */
            if (loop->m_type == rot) {
                new->m_end = loop->m_end;
                list_del(&loop->list);
                kzfree(loop);
            }
            break;
        case 2:
            if (del->m_type == rot) {
                new->m_end = del->m_end;
                list_del(&del->list);
                kzfree(del);
            }
            break;
        case 3:
            if (del->m_type == rot) {
                new->m_end = del->m_end;
                list_del(&del->list);
                kzfree(del);
            }
            else {
                del->m_start = end;
            }
            break;
        default:
            break;
    }

    return new;
}
