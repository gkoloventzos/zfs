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
//#include <sys/zfs_syscalls.h>
#include <linux/slab.h>

/*
 * ret          0 1 2 3            -1
 *              | | | |             |
 *              v v v v             v
 * head -> ( ) -> (   ) -> ( ) -> NULL
 * Returns the node which last touched.
 * Position of the offset in the list
 * ret meaning
 * 0 : between the 2 nodes
 * 1 : Equal with the start of the node
 * 2 : Inside the node
 * 3 : Equal with the end of the node
 * -1 : when it is after the last node. For partial reads mostly.
 */
medium_t *
find_in(struct list_head *head, medium_t *start, bool contin, loff_t posi, int *ret) {

    medium_t *where, *n, *pos;
    where = NULL;
    if (start == NULL)
        return NULL;
    if (contin)
        pos = start;
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
            *ret = 3;
            return where;
        }
        if (posi == pos->m_start) {
            *ret = 1;
            return where;
        }
        *ret = 2;
        return where;
    } while (&pos->list != (head));
    return NULL;
}

/* Interval list of medium of part of file.
 * Debug of this will be done as we do experiments.
 * Notes:
 * New rotation device is always best.
 * Search for start and end.
 * -Start:
 * --If the start is before a node (not currently in the list)
 * or at the beginning then add before.
 * --If it is in the middle:
 * If rotating device the same adjust end. Else split the node and new one.
 * --If is the same as the end of the node:
 * If rotating device is same, change the end. Else check next node.
 * In this section remove all the unwanted nodes between start and end.
 * -End*/
medium_t *
zfs_media_add(struct list_head *dn, loff_t ppos, size_t len, int8_t rot, int only)
{
    int start, stop;
    medium_t *new, *loop, *next, *del, *inter;
    loff_t end = ppos + len;
    loop = new = del = next = NULL;
    start = stop = -1;

    if (len == 0)
        return NULL;
    if (only)
        printk(KERN_EMERG "[LIST] in start %llu end %llu rot %d\n", ppos, end, rot);
    new = kzalloc(sizeof(medium_t), GFP_KERNEL);
    if (new == NULL) {
        printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
        return NULL;
    }
    new->m_start = ppos;
    new->m_end = end;
    new->m_type = rot;
    if (list_empty(dn)) {
        if (only)
            printk(KERN_EMERG "[LIST] list empty start %llu end %llu rot %d\n", ppos, end, rot);
        list_add_tail(&new->list, dn);
        return new;
    }

    /* Find where the begining of this part is supposed to be added.*/
    loop = find_in(dn, list_first_entry(dn, typeof(*new), list), false, ppos, &start);

    /* Probably on read. Reading 10 first and then 10 last lines.
     * Accessing not sequencial parts of file.
     * -1 on start variable*/
    if (loop == NULL) {
        list_add_tail(&new->list, dn);
        return new;
    }

    /* Find where the end of this part is supposed to be added.*/
    del = find_in(dn, loop, true, end, &stop);
    next = loop;

    switch(start) {
        case 0:
        case 1:
            list_add_tail(&new->list, &loop->list);
            break;
        case 2:
            next = list_next_entry(loop, list);
            if (rot != loop->m_type) {
                list_add(&new->list, &loop->list);
                /*If same node break here and return*/
                if (loop == del) {
                    if (stop == 3 && next->m_start == new->m_end && next->m_type == new->m_type) {
                        new->m_end = next->m_end;
                        loop->m_end = new->m_start;
                        list_del(&next->list);
                        kzfree(next);
                        return new;
                    }
                    if(stop != 3) {
                        next = kzalloc(sizeof(medium_t), GFP_KERNEL);
                        if (next == NULL) {
                            printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
                            return NULL;
                        }
                        next->m_end = loop->m_end;
                        next->m_type = loop->m_type;
                        next->m_start = new->m_end;
                        list_add(&next->list, &new->list);
                    }
                    loop->m_end = new->m_start;
                    return new;
                }
                loop->m_end = new->m_start;
            }
            else {
                if (loop->m_end < end)
                    loop->m_end = end;
                kzfree(new);
                if (loop == del) {
                    return loop;
                }
                new = loop;
            }
            break;
        case 3:
            next = list_next_entry(loop, list);
            if (rot == loop->m_type) {
                loop->m_end = new->m_end;
                kzfree(new);
                new = loop;
            }
            else {
                list_add(&new->list, &loop->list);
            }
            break;
        default:
            printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Default in start.\n");
            return NULL;
    }

    /* Remove the excess part */
    while (next != NULL && next != del && &next->list != (dn)) {
        inter = list_next_entry(next, list);
        list_del(&next->list);
        kzfree(next);
        next = inter;
    }

    /* After last node */
    if (del == NULL) {
        new = list_last_entry(dn, typeof(*new), list);
        new->m_end = end;
        return new;
    }

    switch(stop) {
        case 0:
            return new;
        case 1:
            if (del->m_type == new->m_type) {
                new->m_end = del->m_end;
                list_del(&del->list);
                kzfree(del);
                if (start == 2) {
                    loop->m_end = new->m_start;
                }
            }
            return new;
        case 2:
            if (del->m_type == new->m_type) {
                new->m_end = del->m_end;
                list_del(&del->list);
                kzfree(del);
                break;
            }
            del->m_start = end;
            break;
        case 3:
            next = list_prev_entry(del, list);
            list_del(&del->list);
            kzfree(del);
            if (new != next && new->m_start == next->m_end && next->m_type == new->m_type) {
                new->m_end = next->m_end;
                list_del(&next->list);
                kzfree(next);
            }
            next = list_next_entry(new, list);
            if (new != next && new->m_end == next->m_start && next->m_type == new->m_type) {
                new->m_end = next->m_end;
                list_del(&next->list);
                kzfree(next);
            }
            break;
        default:
            printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Default in stop.\n");
            return NULL;
    }

    return new;
}

struct list_head *
get_media_storage(struct list_head *dn, loff_t ppos, loff_t pend, int *size)
{
    struct medium *nh, *new, *loop, *del, *next, *prev;
    int start, stop;
    struct list_head *ret = NULL;

    loop = find_in(dn, list_first_entry(dn, typeof(*new), list), false, ppos, &start);
    if (loop == NULL || start < 0)
        return NULL;

    del = find_in(dn, loop, true, pend, &stop);
    if (loop == del && start == 0 && stop < 2)
        return NULL;
    ret = kzalloc(sizeof(struct list_head), GFP_KERNEL);
    if (ret == NULL) {
        printk(KERN_EMERG "[ERROR][GET_MEDIA]Cannot allocate list\n");
        return NULL;
    }
    INIT_LIST_HEAD(ret);

    new = kzalloc(sizeof(medium_t), GFP_KERNEL);
    if (new == NULL) {
        printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
        kzfree(ret);
        return NULL;
    }
    switch (start) {
        case 0:
            new->m_start = ppos;
            new->m_end = loop->m_start;
            new->m_type = -1;
            list_add_tail(&new->list, ret);
            ++(*size);
            break;
        case 1:
        case 2:
            if (loop == del) {
                new->m_start = ppos;
                new->m_type = loop->m_type;
                list_add_tail(&new->list, ret);
                ++(*size);
                if (stop == 2) {
                    new->m_end = pend;
                    return ret;
                }
                else if (stop == 3) {
                    new->m_end = loop->m_end;
                    return ret;
                }
                nh = new;
                new = kzalloc(sizeof(medium_t), GFP_KERNEL);
                if (new == NULL) {
                    printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
                    kzfree(ret);
                    return NULL;
                }
                new->m_start = loop->m_end;
                new->m_end = pend;
                new->m_type = -1;
                list_add_tail(&nh->list, &new->list);
                ++(*size);
                return ret;
            }
            new->m_start = ppos;
            new->m_end = loop->m_end;
            new->m_type = loop->m_type;
            list_add_tail(&new->list, ret);
            ++(*size);
            break;
        case 3:
            if (loop == del) {
                if (stop == -1) {
                    new->m_start = ppos;
                    new->m_end = loop->m_start;
                    new->m_type = -1;
                    list_add_tail(&new->list, ret);
                    ++(*size);
                    return ret;
                }
                return NULL;
            }
            break;
    }

    next = list_next_entry(loop, list);
    while (next != NULL && next != del && &next->list != (dn)) {
        new = kzalloc(sizeof(medium_t), GFP_KERNEL);
        if (new == NULL) {
            printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
            kzfree(ret);
            return NULL;
        }
        new->m_start = next->m_start;
        new->m_end = next->m_end;
        new->m_type = next->m_type;
        list_add_tail(&new->list, ret);
        ++(*size);
        next = list_next_entry(next, list);
    }

    new = kzalloc(sizeof(medium_t), GFP_KERNEL);
    if (new == NULL) {
        printk(KERN_EMERG "[ERROR][ZFS_MEDIA_ADD]Cannot allocate for new medium\n");
        kzfree(ret);
        return NULL;
    }
    /*We have dealt with loop == del on switch of start*/
    switch(stop) {
        case 2:
        case 3:
            new->m_start = next->m_start;
            new->m_end = pend;
            new->m_type = next->m_type;
            list_add_tail(&new->list, ret);
            ++(*size);
            break;
        case 0:
        case 1:
        default:
            prev = list_prev_entry(next, list);
            new->m_start = prev->m_end;
            new->m_end = pend;
            new->m_type = -1;
            list_add_tail(&new->list, ret);
            ++(*size);
            break;
    }
    return ret;
}
