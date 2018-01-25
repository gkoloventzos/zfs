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
 * Copyright (c) 2011, Lawrence Livermore National Security, LLC.
 * Copyright (c) 2015 by Chunwei Chen. All rights reserved.
 */


#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#include <sys/dmu_objset.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_media.h>
#include <sys/zpl.h>
#include <sys/boot_files.h>
#include <sys/hetfs.h>
#include <sys/dnode.h>
#include <sys/dbuf.h>

#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/sha.h>

struct rb_root *hetfs_tree = NULL;
EXPORT_SYMBOL(hetfs_tree);
int only_one = 0;
int bla = 0;
char *only_name = NULL;
static DEFINE_SEMAPHORE(tree_lock);

void my_delete_list(struct list_head *dn)
{
    struct list_head *pos, *q;
    struct medium *tmp;

    list_for_each_safe(pos, q, dn){
         tmp = list_entry(pos, struct medium, list);
         list_del(pos);
         kzfree(tmp);
    }
}

int init_tree(void)
{
	    hetfs_tree = kmem_zalloc(sizeof(struct rb_root),GFP_KERNEL);
        if (hetfs_tree == NULL) {
            printk(KERN_EMERG "[ERROR] Cannot alloc mem for name\n");
            return 1;
        }
        *hetfs_tree = RB_ROOT;
        return 0;
}

int init_data(struct data *InsNode, struct dentry *dentry)
{
    InsNode->read_reqs = kmem_zalloc(sizeof(struct list_head), GFP_KERNEL);
    if (InsNode->read_reqs == NULL) {
        printk(KERN_EMERG "[ERROR]InsNode read null after malloc\n");
        return 1;
    }
    InsNode->write_reqs = kmem_zalloc(sizeof(struct list_head), GFP_KERNEL);
    if (InsNode->write_reqs == NULL) {
        printk(KERN_EMERG "[ERROR]InsNode write null after malloc\n");
        kzfree(InsNode->read_reqs);
        return 1;
    }
    InsNode->list_read_rot = kmem_zalloc(sizeof(struct list_head), GFP_KERNEL);
    if (InsNode->list_read_rot == NULL) {
        printk(KERN_EMERG "[ERROR]InsNode read null after malloc\n");
        kzfree(InsNode->read_reqs);
        kzfree(InsNode->write_reqs);
        return 1;
    }
    InsNode->list_write_rot = kmem_zalloc(sizeof(struct list_head), GFP_KERNEL);
    if (InsNode->list_write_rot == NULL) {
        printk(KERN_EMERG "[ERROR]InsNode read null after malloc\n");
        kzfree(InsNode->read_reqs);
        kzfree(InsNode->write_reqs);
        kzfree(InsNode->list_read_rot);
        return 1;
    }
    INIT_LIST_HEAD(InsNode->list_read_rot);
    INIT_LIST_HEAD(InsNode->list_write_rot);
    INIT_LIST_HEAD(InsNode->read_reqs);
    INIT_LIST_HEAD(InsNode->write_reqs);
    InsNode->read_all_file = 100;
    InsNode->write_all_file = 0;
    InsNode->write_rot = -2;
    InsNode->deleted = 0;
    InsNode->to_rot = -1;
    init_rwsem(&(InsNode->read_sem));
    init_rwsem(&(InsNode->write_sem));
/*    bla++;
    if (bla%100 == 0)
        printk(KERN_EMERG "[INIT_DATA]Tree nodes %d\n", bla);*/
    return 0;
}

void fullname(struct dentry *dentry, char *name, int *stop)
{
    zfs_sb_t *zsb = NULL;
    struct inode *ip = NULL;

    ip = d_inode(dentry);
    if (ip != NULL) {
        zsb = ITOZSB(ip);

        if (zsb->z_mntopts->z_mntpoint != NULL) {
            if (strncmp(name, zsb->z_mntopts->z_mntpoint, strlen(zsb->z_mntopts->z_mntpoint)) != 0) {
                strncat(name, zsb->z_mntopts->z_mntpoint,
                    strlen(zsb->z_mntopts->z_mntpoint));
            }
        }
    }
    if (dentry == dentry->d_parent)
        *stop =-1;
    while((void *)dentry != (void *)dentry->d_parent && *stop >= 0) {
        if (*stop < 0 || *stop > 10) {
            *stop =-1;
            return;
        }
        (*stop)++;
        fullname(dentry->d_parent, name, stop);
    }
    strncat(name, dentry->d_name.name, strlen(dentry->d_name.name));
    if ((void *)dentry != (void *)dentry->d_parent && \
        !list_empty(&dentry->d_child) && \
        !list_empty(&dentry->d_subdirs)) {
        strncat(name,"/",1);
    }
}

struct data *tree_insearch(struct dentry *dentry, char *filename)
{
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    unsigned char *output;
    struct data *InsNode, *OutNode;
    int stop = 0;

    if (filename == NULL) {
        if (dentry == NULL) {
            printk(KERN_EMERG "[ERROR] Both Dentry and filename is empty\n");
            return NULL;
        }
        filename = kzalloc((PATH_MAX+NAME_MAX)*sizeof(char),GFP_KERNEL);
        if (filename == NULL) {
            printk(KERN_EMERG "[ERROR] Cannot alloc mem for name\n");
            return NULL;
        }
        fullname(dentry, filename, &stop);
    }
    output = kzalloc(SHA512_DIGEST_SIZE+1, GFP_KERNEL);
    if (output == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc mem for hash\n");
        kzfree(filename);
        return NULL;
    }

    tfm = crypto_alloc_hash("sha512", 0, CRYPTO_ALG_ASYNC);
    desc.tfm = tfm;
    desc.flags = 0;
    sg_init_one(&sg, filename, strlen(filename));
    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, strlen(filename));
    crypto_hash_final(&desc, output);
    crypto_free_hash(tfm);
    InsNode = kzalloc(sizeof(struct data), GFP_KERNEL);
    if (InsNode == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc memory for InsNode\n");
        kzfree(filename);
        kzfree(output);
        return NULL;
    }
    InsNode->hash = output;

    down_write(&tree_sem);
    OutNode = rb_insert(hetfs_tree, InsNode);

    if (OutNode == NULL || InsNode == NULL)
        return NULL;
    if (OutNode == InsNode)
        init_data(OutNode, dentry);
    else {
        kzfree(output);
        kzfree(InsNode);
    }
    up_write(&tree_sem);

    return OutNode;
}

static int
zpl_open(struct inode *ip, struct file *filp)
{
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	error = generic_file_open(ip, filp);
	if (error)
		return (error);

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_open(ip, filp->f_mode, filp->f_flags, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_release(struct inode *ip, struct file *filp)
{
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	cookie = spl_fstrans_mark();
	if (ITOZ(ip)->z_atime_dirty)
		zfs_mark_inode_dirty(ip);

	crhold(cr);
	error = -zfs_close(ip, filp->f_flags, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

static int
zpl_iterate(struct file *filp, struct dir_context *ctx)
{
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_readdir(file_inode(filp), ctx, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#if !defined(HAVE_VFS_ITERATE) && !defined(HAVE_VFS_ITERATE_SHARED)
static int
zpl_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct dir_context ctx = DIR_CONTEXT_INIT(dirent, filldir, filp->f_pos);
	int error;

	error = zpl_iterate(filp, &ctx);
	filp->f_pos = ctx.pos;

	return (error);
}
#endif /* HAVE_VFS_ITERATE */

#if defined(HAVE_FSYNC_WITH_DENTRY)
/*
 * Linux 2.6.x - 2.6.34 API,
 * Through 2.6.34 the nfsd kernel server would pass a NULL 'file struct *'
 * to the fops->fsync() hook.  For this reason, we must be careful not to
 * use filp unconditionally.
 */
static int
zpl_fsync(struct file *filp, struct dentry *dentry, int datasync)
{
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_fsync(dentry->d_inode, datasync, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#ifdef HAVE_FILE_AIO_FSYNC
static int
zpl_aio_fsync(struct kiocb *kiocb, int datasync)
{
	struct file *filp = kiocb->ki_filp;
	return (zpl_fsync(filp, file_dentry(filp), datasync));
}
#endif

#elif defined(HAVE_FSYNC_WITHOUT_DENTRY)
/*
 * Linux 2.6.35 - 3.0 API,
 * As of 2.6.35 the dentry argument to the fops->fsync() hook was deemed
 * redundant.  The dentry is still accessible via filp->f_path.dentry,
 * and we are guaranteed that filp will never be NULL.
 */
static int
zpl_fsync(struct file *filp, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_fsync(inode, datasync, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#ifdef HAVE_FILE_AIO_FSYNC
static int
zpl_aio_fsync(struct kiocb *kiocb, int datasync)
{
	return (zpl_fsync(kiocb->ki_filp, datasync));
}
#endif

#elif defined(HAVE_FSYNC_RANGE)
/*
 * Linux 3.1 - 3.x API,
 * As of 3.1 the responsibility to call filemap_write_and_wait_range() has
 * been pushed down in to the .fsync() vfs hook.  Additionally, the i_mutex
 * lock is no longer held by the caller, for zfs we don't require the lock
 * to be held so we don't acquire it.
 */
static int
zpl_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	cred_t *cr = CRED();
	int error;
	fstrans_cookie_t cookie;

	error = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (error)
		return (error);

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_fsync(inode, datasync, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);
	ASSERT3S(error, <=, 0);

	return (error);
}

#ifdef HAVE_FILE_AIO_FSYNC
static int
zpl_aio_fsync(struct kiocb *kiocb, int datasync)
{
	return (zpl_fsync(kiocb->ki_filp, kiocb->ki_pos, -1, datasync));
}
#endif

#else
#error "Unsupported fops->fsync() implementation"
#endif

static ssize_t
zpl_read_common_iovec(struct inode *ip, const struct iovec *iovp, size_t count,
    unsigned long nr_segs, loff_t *ppos, uio_seg_t segment, int flags,
    cred_t *cr, size_t skip, int8_t *rot, bool rewrite)
{
	ssize_t read;
	uio_t uio;
	int error;
	fstrans_cookie_t cookie;

	uio.uio_iov = iovp;
	uio.uio_skip = skip;
	uio.uio_resid = count;
	uio.uio_iovcnt = nr_segs;
	uio.uio_loffset = *ppos;
	uio.uio_limit = MAXOFFSET_T;
	uio.uio_segflg = segment;
    uio.uio_rewrite = rewrite;

	cookie = spl_fstrans_mark();
	error = -zfs_read(ip, &uio, flags, cr, rot);
	spl_fstrans_unmark(cookie);
	if (error < 0)
		return (error);

	read = count - uio.uio_resid;
	*ppos += read;
	task_io_account_read(read);

	return (read);
}

inline ssize_t
zpl_read_common(struct inode *ip, const char *buf, size_t len, loff_t *ppos,
    uio_seg_t segment, int flags, cred_t *cr, int8_t *rot, bool rewrite)
{
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	return (zpl_read_common_iovec(ip, &iov, len, 1, ppos, segment,
	    flags, cr, 0, rot, rewrite));
}

static ssize_t
re_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    cred_t *cr = CRED();
    ssize_t read;
    //int8_t rot = -5;

    //printk(KERN_EMERG "[RE_READ]If not rewrite what the fuck I am doing here\n");
    crhold(cr);
    read = zpl_read_common(filp->f_mapping->host, buf, len, ppos,
       UIO_USERSPACE, filp->f_flags, cr, NULL, true);
       //UIO_USERSPACE, filp->f_flags, cr, &rot);
    crfree(cr);

    return (read);
}

static ssize_t
zpl_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	cred_t *cr = CRED();
	ssize_t read;

    struct task_struct *thread1;
    struct timespec arrival_time;
    struct kdata *kdata = NULL;
    loff_t start_ppos = *ppos;
    int8_t *rot;
    dnode_t *dn;
    char *filename = NULL;
    znode_t     *zp = ITOZ(filp->f_mapping->host);

    ktime_get_ts(&arrival_time);
    rot = kzalloc(sizeof(int), GFP_KERNEL);
    *rot = -2;

    down(&tree_lock);
    if (hetfs_tree == NULL)
        init_tree();
    up(&tree_lock);

    DB_DNODE_ENTER((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    dn = DB_DNODE((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    mutex_enter(&dn->dn_mtx);
    if (dn->cadmus == NULL)
        dn->cadmus = tree_insearch(file_dentry(filp), filename);
    mutex_exit(&dn->dn_mtx);

    dn->cadmus->dentry = file_dentry(filp);
    DB_DNODE_EXIT((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
	crhold(cr);
	read = zpl_read_common(filp->f_mapping->host, buf, len, ppos,
	    UIO_USERSPACE, filp->f_flags, cr, rot, false);
	crfree(cr);

    if (read > 0 && dn->cadmus != NULL) {
        kdata = kzalloc(sizeof(struct kdata), GFP_KERNEL);
        if (kdata != NULL) {
            kdata->InsNode = dn->cadmus;
            kdata->filp = filp;
            kdata->dentry = file_dentry(filp);
            kdata->type = HET_READ;
            kdata->offset = start_ppos;
            kdata->length = read;
            kdata->rot = rot;
            kdata->time = arrival_time.tv_sec*1000000000L + arrival_time.tv_nsec;
            thread1 = kthread_run(add_request, (void *) kdata,"readreq");
        }
        else
            printk(KERN_EMERG "[ERROR] Kdata null read\n");
    }
    else
        kzfree(rot);

    kzfree(filename);
	file_accessed(filp);
	return (read);
}



static ssize_t
zpl_iter_read_common(struct kiocb *kiocb, const struct iovec *iovp,
    unsigned long nr_segs, size_t count, uio_seg_t seg, size_t skip)
{
	cred_t *cr = CRED();
	struct file *filp = kiocb->ki_filp;
	ssize_t read;

	crhold(cr);
	read = zpl_read_common_iovec(filp->f_mapping->host, iovp, count,
	    nr_segs, &kiocb->ki_pos, seg, filp->f_flags, cr, skip, NULL, false);
	crfree(cr);

	file_accessed(filp);
	return (read);
}

#if defined(HAVE_VFS_RW_ITERATE)
static ssize_t
zpl_iter_read(struct kiocb *kiocb, struct iov_iter *to)
{
	ssize_t ret;
	uio_seg_t seg = UIO_USERSPACE;
	if (to->type & ITER_KVEC)
		seg = UIO_SYSSPACE;
	if (to->type & ITER_BVEC)
		seg = UIO_BVEC;
	ret = zpl_iter_read_common(kiocb, to->iov, to->nr_segs,
	    iov_iter_count(to), seg, to->iov_offset);
	if (ret > 0)
		iov_iter_advance(to, ret);
	return (ret);
}
#else
static ssize_t
zpl_aio_read(struct kiocb *kiocb, const struct iovec *iovp,
    unsigned long nr_segs, loff_t pos)
{
	return (zpl_iter_read_common(kiocb, iovp, nr_segs, kiocb->ki_nbytes,
	    UIO_USERSPACE, 0));
}
#endif /* HAVE_VFS_RW_ITERATE */

static ssize_t
zpl_write_common_iovec(struct inode *ip, const struct iovec *iovp, size_t count,
    unsigned long nr_segs, loff_t *ppos, uio_seg_t segment, int flags,
    cred_t *cr, size_t skip, bool rewrite, int8_t rot)
{
	ssize_t wrote;
	uio_t uio;
	int error;
	fstrans_cookie_t cookie;

	if (flags & O_APPEND)
		*ppos = i_size_read(ip);

	uio.uio_iov = iovp;
	uio.uio_skip = skip;
	uio.uio_resid = count;
	uio.uio_iovcnt = nr_segs;
	uio.uio_loffset = *ppos;
	uio.uio_limit = MAXOFFSET_T;
	uio.uio_segflg = segment;
    uio.uio_rewrite = rewrite;
    uio.uio_rot = rot;

	cookie = spl_fstrans_mark();
	error = -zfs_write(ip, &uio, flags, cr);
	spl_fstrans_unmark(cookie);
	if (error < 0)
		return (error);

	wrote = count - uio.uio_resid;
	*ppos += wrote;
	task_io_account_write(wrote);

	return (wrote);
}
inline ssize_t
zpl_write_common(struct inode *ip, const char *buf, size_t len, loff_t *ppos,
    uio_seg_t segment, int flags, cred_t *cr, bool rewrite, dnode_t *dn)
{
	struct iovec iov;
    struct medium *loop, *nh;
    struct list_head *list_rot;
	ssize_t wrote_gen = 0;
    loff_t start_pos = *ppos;
    int size = 0;
    ssize_t error = 0;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

    if (dn != NULL && dn->cadmus != NULL && !list_empty(dn->cadmus->list_write_rot)) {
        start_pos = *ppos;
        list_rot = get_media_storage(dn->cadmus->list_write_rot, start_pos, start_pos+len, &size);
        if (list_rot == NULL)
            goto single;
        if (size == 1) {
            /*If only one avoid all those loops*/
            loop = list_first_entry_or_null(list_rot, typeof(*(loop)) ,list);
            my_delete_list(list_rot);
            return (zpl_write_common_iovec(ip, &iov, len, 1, ppos, segment,
                        flags, cr, 0, rewrite, loop->m_type));
        }
//        printk(KERN_EMERG "[LIST]rot %p size %d start %lld end %lld\n", list_rot, size, start_pos, start_pos+len);
        list_for_each_entry_safe(loop, nh, list_rot, list) {
            len = loop->m_end-loop->m_start;
            rewrite = true;
            printk(KERN_EMERG "[LIST] pointer %p start %lld end %lld len %ld rot %d\n", loop, loop->m_start, loop->m_end, len, loop->m_type);
            loop->write_ret = zpl_write_common_iovec(ip, &iov, len, 1, ppos, segment,
                    flags, cr, wrote_gen, rewrite, loop->m_type);
            wrote_gen += len;
        }
        while(error != size) {
            error = 0;
            wrote_gen = 0;
            list_for_each_entry_safe(loop, nh, list_rot, list) {
                if (loop->write_ret != 0)
                    ++error;
            }
            wrote_gen += loop->write_ret;
        }
        list_for_each_entry_safe(loop, nh, list_rot, list) {
            if (loop->write_ret < 0) {
                wrote_gen = loop->write_ret;
                break;
            }
        }
        my_delete_list(list_rot);
        return wrote_gen;
    }
single:
    return (zpl_write_common_iovec(ip, &iov, len, 1, ppos, segment,
                flags, cr, 0, rewrite, -4));
}

static ssize_t
zpl_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	cred_t *cr = CRED();
	ssize_t wrote;
    const char *name;
    dnode_t *dn;
    struct task_struct *thread1;
    struct kdata *kdata;
    struct timespec arrival_time;
    int8_t rot = -1;
    struct data *InsNode = NULL;
    int stop = 0;
    loff_t start_ppos = *ppos;
    char *filename = NULL;
    znode_t     *zp = ITOZ(filp->f_mapping->host);
    bool print = false;

    ktime_get_ts(&arrival_time);
	crhold(cr);

    down(&tree_lock);
    if (hetfs_tree == NULL)
        init_tree();
    up(&tree_lock);
    name = file_dentry(filp)->d_name.name;

    DB_DNODE_ENTER((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    dn = DB_DNODE((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    filename = kzalloc((PATH_MAX+NAME_MAX)*sizeof(char),GFP_KERNEL);
    if (filename == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc mem for name\n");
        goto err;
    }
    fullname(file_dentry(filp), filename, &stop);
    mutex_enter(&dn->dn_mtx);
    if (dn->cadmus == NULL)
        dn->cadmus = tree_insearch(file_dentry(filp), filename);
    mutex_exit(&dn->dn_mtx);

    InsNode = dn->cadmus;
    InsNode->dentry = file_dentry(filp);
    if (InsNode != NULL) {
        if (strstr(filename, "/log/") == NULL) {
            if (InsNode->write_rot > -1 && dn->dn_write_rot != InsNode->write_rot) {
                dn->dn_write_rot = InsNode->write_rot;
                rot = InsNode->write_rot;
            }
        }
        else {
            /* We do not care about logs*/
            dn = NULL;
            goto err;
        }
        if (strstr(filename, "sample_ssd") != NULL) {
            rot = METASLAB_ROTOR_VDEV_TYPE_SSD;
            print = true;
            dn->dn_write_rot = -1;
/*            down_write(&(InsNode->write_sem));
            zfs_media_add(InsNode->list_write_rot, start_ppos, len, rot, 0);
            up_write(&(InsNode->write_sem));
            InsNode->write_rot = rot;
            dn->dn_write_rot = rot;*/
        }
        else {
            for (stop = 0; stop <= 195; stop++) {
                if (strstr(filename, boot_files[stop]) != NULL) {
                    rot = METASLAB_ROTOR_VDEV_TYPE_SSD;
                    break;
                }
            }
            dn->dn_write_rot = rot;
        }

/*        down_write(&(InsNode->write_sem));
        zfs_media_add(InsNode->list_write_rot, start_ppos, len, rot, 0);
        up_write(&(InsNode->write_sem));*/
    }

/*    if (strstr(filename, "sample_ssd") != NULL) {
        printk(KERN_EMERG "[LIST]size %ld start %lld end %lld insnode %p\n", len, *ppos, *ppos+len, dn->cadmus);
    }*/

    DB_DNODE_EXIT((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));

err:
	wrote = zpl_write_common(filp->f_mapping->host, buf, len, ppos,
	    UIO_USERSPACE, filp->f_flags, cr, print, dn);
	crfree(cr);

    if (wrote > 0 && InsNode != NULL) {
        kdata = kzalloc(sizeof(struct kdata), GFP_KERNEL);
        if (kdata != NULL) {
            kdata->InsNode = (dn != NULL ? dn->cadmus : NULL);
            kdata->filp = filp;
            kdata->dentry = file_dentry(filp);
            kdata->type = HET_WRITE;
            kdata->offset = start_ppos;
            kdata->length = wrote;
            kdata->rot = &dn->dn_write_rot;
            kdata->time = arrival_time.tv_sec*1000000000L + arrival_time.tv_nsec;
            thread1 = kthread_run(add_request, (void *) kdata,"writereq");
        }
        else
            printk(KERN_EMERG "[ERROR] Kdata null write\n");
    }

    kzfree(filename);
	return (wrote);
}

static ssize_t
re_write(struct file *filp, const char *buf, size_t len, loff_t *ppos)
{
	cred_t *cr = CRED();
	ssize_t wrote;
    char *filename;
    dnode_t *dn;
    int stop = 0;
    znode_t     *zp = ITOZ(filp->f_mapping->host);

    crhold(cr);

    filename = kzalloc((PATH_MAX+NAME_MAX)*sizeof(char),GFP_KERNEL);
    if (filename == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc mem for name\n");
    }
    fullname(file_dentry(filp), filename, &stop);
    DB_DNODE_ENTER((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    dn = DB_DNODE((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));
    mutex_enter(&dn->dn_mtx);
    dn->cadmus = tree_insearch(file_dentry(filp), filename);
    mutex_exit(&dn->dn_mtx);
    DB_DNODE_EXIT((dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl));

	wrote = zpl_write_common(filp->f_mapping->host, buf, len, ppos,
	    UIO_USERSPACE, filp->f_flags, cr, true, dn);
	crfree(cr);

	return (wrote);
}

int
zpl_rewrite(struct file *filp)
{
    ssize_t reread = 0;
    ssize_t rewrite = 0;
    loff_t pos = 0;
    loff_t start_pos = 0;
    loff_t npos = 0;
    size_t len = 4096;
    char *buf = kzalloc(len, GFP_KERNEL);

    if (filp == NULL) {
        printk(KERN_EMERG "[ERROR]zpl_rewrite - filp NULL\n");
        return 1;
    }
    if (filp->f_mapping == NULL) {
        printk(KERN_EMERG "[ERROR]zpl_rewrite - filp->f_mapping NULL\n");
        return 1;
    }
    if (filp->f_mapping->host == NULL) {
        printk(KERN_EMERG "[ERROR]zpl_rewrite - filp->f_mapping->host NULL\n");
        return 1;
    }
    buf = kzalloc(sizeof(char) * len, GFP_KERNEL);
    if (buf == NULL) {
        printk(KERN_EMERG "[ERROR]zpl_rewrite - Cannot allocate buf\n");
        return 1;
    }
    for(;;) {
        reread = re_read(filp, buf, len, &pos);
        if (reread > 0) {
            rewrite = re_write(filp, buf, reread, &npos);
            if (reread != rewrite) {
                printk(KERN_EMERG "[ERROR]ZPL_REWRITE %lld %lld error %zd\n", start_pos, npos, reread);
                break;
            }
            start_pos += reread;
            pos = start_pos;
            memset(buf, 0, len);
            continue;
        }
        else if (reread < 0){
            printk(KERN_EMERG "[ERROR]ZPL_REWRITE %lld %lld error %zd\n", start_pos, npos, reread);
        }
        break;
    }
    kzfree(buf);
    return 0;
}

static ssize_t
zpl_iter_write_common(struct kiocb *kiocb, const struct iovec *iovp,
    unsigned long nr_segs, size_t count, uio_seg_t seg, size_t skip)
{
	cred_t *cr = CRED();
	struct file *filp = kiocb->ki_filp;
	ssize_t wrote;

	crhold(cr);
	wrote = zpl_write_common_iovec(filp->f_mapping->host, iovp, count,
	    nr_segs, &kiocb->ki_pos, seg, filp->f_flags, cr, skip, false, -5);
	crfree(cr);

	return (wrote);
}

#if defined(HAVE_VFS_RW_ITERATE)
static ssize_t
zpl_iter_write(struct kiocb *kiocb, struct iov_iter *from)
{
	ssize_t ret;
	uio_seg_t seg = UIO_USERSPACE;
	if (from->type & ITER_KVEC)
		seg = UIO_SYSSPACE;
	if (from->type & ITER_BVEC)
		seg = UIO_BVEC;
	ret = zpl_iter_write_common(kiocb, from->iov, from->nr_segs,
	    iov_iter_count(from), seg, from->iov_offset);
	if (ret > 0)
		iov_iter_advance(from, ret);
	return (ret);
}
#else
static ssize_t
zpl_aio_write(struct kiocb *kiocb, const struct iovec *iovp,
    unsigned long nr_segs, loff_t pos)
{
	return (zpl_iter_write_common(kiocb, iovp, nr_segs, kiocb->ki_nbytes,
	    UIO_USERSPACE, 0));
}
#endif /* HAVE_VFS_RW_ITERATE */

static loff_t
zpl_llseek(struct file *filp, loff_t offset, int whence)
{
#if defined(SEEK_HOLE) && defined(SEEK_DATA)
	fstrans_cookie_t cookie;

	if (whence == SEEK_DATA || whence == SEEK_HOLE) {
		struct inode *ip = filp->f_mapping->host;
		loff_t maxbytes = ip->i_sb->s_maxbytes;
		loff_t error;

		spl_inode_lock_shared(ip);
		cookie = spl_fstrans_mark();
		error = -zfs_holey(ip, whence, &offset);
		spl_fstrans_unmark(cookie);
		if (error == 0)
			error = lseek_execute(filp, ip, offset, maxbytes);
		spl_inode_unlock_shared(ip);

		return (error);
	}
#endif /* SEEK_HOLE && SEEK_DATA */

	return (generic_file_llseek(filp, offset, whence));
}

/*
 * It's worth taking a moment to describe how mmap is implemented
 * for zfs because it differs considerably from other Linux filesystems.
 * However, this issue is handled the same way under OpenSolaris.
 *
 * The issue is that by design zfs bypasses the Linux page cache and
 * leaves all caching up to the ARC.  This has been shown to work
 * well for the common read(2)/write(2) case.  However, mmap(2)
 * is problem because it relies on being tightly integrated with the
 * page cache.  To handle this we cache mmap'ed files twice, once in
 * the ARC and a second time in the page cache.  The code is careful
 * to keep both copies synchronized.
 *
 * When a file with an mmap'ed region is written to using write(2)
 * both the data in the ARC and existing pages in the page cache
 * are updated.  For a read(2) data will be read first from the page
 * cache then the ARC if needed.  Neither a write(2) or read(2) will
 * will ever result in new pages being added to the page cache.
 *
 * New pages are added to the page cache only via .readpage() which
 * is called when the vfs needs to read a page off disk to back the
 * virtual memory region.  These pages may be modified without
 * notifying the ARC and will be written out periodically via
 * .writepage().  This will occur due to either a sync or the usual
 * page aging behavior.  Note because a read(2) of a mmap'ed file
 * will always check the page cache first even when the ARC is out
 * of date correct data will still be returned.
 *
 * While this implementation ensures correct behavior it does have
 * have some drawbacks.  The most obvious of which is that it
 * increases the required memory footprint when access mmap'ed
 * files.  It also adds additional complexity to the code keeping
 * both caches synchronized.
 *
 * Longer term it may be possible to cleanly resolve this wart by
 * mapping page cache pages directly on to the ARC buffers.  The
 * Linux address space operations are flexible enough to allow
 * selection of which pages back a particular index.  The trick
 * would be working out the details of which subsystem is in
 * charge, the ARC, the page cache, or both.  It may also prove
 * helpful to move the ARC buffers to a scatter-gather lists
 * rather than a vmalloc'ed region.
 */
static int
zpl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct inode *ip = filp->f_mapping->host;
	znode_t *zp = ITOZ(ip);
	int error;
	fstrans_cookie_t cookie;

	cookie = spl_fstrans_mark();
	error = -zfs_map(ip, vma->vm_pgoff, (caddr_t *)vma->vm_start,
	    (size_t)(vma->vm_end - vma->vm_start), vma->vm_flags);
	spl_fstrans_unmark(cookie);
	if (error)
		return (error);

	error = generic_file_mmap(filp, vma);
	if (error)
		return (error);

	mutex_enter(&zp->z_lock);
	zp->z_is_mapped = 1;
	mutex_exit(&zp->z_lock);

	return (error);
}

/*
 * Populate a page with data for the Linux page cache.  This function is
 * only used to support mmap(2).  There will be an identical copy of the
 * data in the ARC which is kept up to date via .write() and .writepage().
 *
 * Current this function relies on zpl_read_common() and the O_DIRECT
 * flag to read in a page.  This works but the more correct way is to
 * update zfs_fillpage() to be Linux friendly and use that interface.
 */
static int
zpl_readpage(struct file *filp, struct page *pp)
{
	struct inode *ip;
	struct page *pl[1];
	int error = 0;
	fstrans_cookie_t cookie;

	ASSERT(PageLocked(pp));
	ip = pp->mapping->host;
	pl[0] = pp;

	cookie = spl_fstrans_mark();
	error = -zfs_getpage(ip, pl, 1);
	spl_fstrans_unmark(cookie);

	if (error) {
		SetPageError(pp);
		ClearPageUptodate(pp);
	} else {
		ClearPageError(pp);
		SetPageUptodate(pp);
		flush_dcache_page(pp);
	}

	unlock_page(pp);
	return (error);
}

/*
 * Populate a set of pages with data for the Linux page cache.  This
 * function will only be called for read ahead and never for demand
 * paging.  For simplicity, the code relies on read_cache_pages() to
 * correctly lock each page for IO and call zpl_readpage().
 */
static int
zpl_readpages(struct file *filp, struct address_space *mapping,
    struct list_head *pages, unsigned nr_pages)
{
	return (read_cache_pages(mapping, pages,
	    (filler_t *)zpl_readpage, filp));
}

int
zpl_putpage(struct page *pp, struct writeback_control *wbc, void *data)
{
	struct address_space *mapping = data;
	fstrans_cookie_t cookie;

	ASSERT(PageLocked(pp));
	ASSERT(!PageWriteback(pp));

	cookie = spl_fstrans_mark();
	(void) zfs_putpage(mapping->host, pp, wbc);
	spl_fstrans_unmark(cookie);

	return (0);
}

static int
zpl_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	znode_t		*zp = ITOZ(mapping->host);
	zfs_sb_t	*zsb = ITOZSB(mapping->host);
	enum writeback_sync_modes sync_mode;
	int result;

	ZFS_ENTER(zsb);
	if (zsb->z_os->os_sync == ZFS_SYNC_ALWAYS)
		wbc->sync_mode = WB_SYNC_ALL;
	ZFS_EXIT(zsb);
	sync_mode = wbc->sync_mode;

	/*
	 * We don't want to run write_cache_pages() in SYNC mode here, because
	 * that would make putpage() wait for a single page to be committed to
	 * disk every single time, resulting in atrocious performance. Instead
	 * we run it once in non-SYNC mode so that the ZIL gets all the data,
	 * and then we commit it all in one go.
	 */
	wbc->sync_mode = WB_SYNC_NONE;
	result = write_cache_pages(mapping, wbc, zpl_putpage, mapping);
	if (sync_mode != wbc->sync_mode) {
		ZFS_ENTER(zsb);
		ZFS_VERIFY_ZP(zp);
		if (zsb->z_log != NULL)
			zil_commit(zsb->z_log, zp->z_id);
		ZFS_EXIT(zsb);

		/*
		 * We need to call write_cache_pages() again (we can't just
		 * return after the commit) because the previous call in
		 * non-SYNC mode does not guarantee that we got all the dirty
		 * pages (see the implementation of write_cache_pages() for
		 * details). That being said, this is a no-op in most cases.
		 */
		wbc->sync_mode = sync_mode;
		result = write_cache_pages(mapping, wbc, zpl_putpage, mapping);
	}
	return (result);
}

/*
 * Write out dirty pages to the ARC, this function is only required to
 * support mmap(2).  Mapped pages may be dirtied by memory operations
 * which never call .write().  These dirty pages are kept in sync with
 * the ARC buffers via this hook.
 */
static int
zpl_writepage(struct page *pp, struct writeback_control *wbc)
{
	if (ITOZSB(pp->mapping->host)->z_os->os_sync == ZFS_SYNC_ALWAYS)
		wbc->sync_mode = WB_SYNC_ALL;

	return (zpl_putpage(pp, wbc, pp->mapping));
}

/*
 * The only flag combination which matches the behavior of zfs_space()
 * is FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE.  The FALLOC_FL_PUNCH_HOLE
 * flag was introduced in the 2.6.38 kernel.
 */
#if defined(HAVE_FILE_FALLOCATE) || defined(HAVE_INODE_FALLOCATE)
long
zpl_fallocate_common(struct inode *ip, int mode, loff_t offset, loff_t len)
{
	int error = -EOPNOTSUPP;

#if defined(FALLOC_FL_PUNCH_HOLE) && defined(FALLOC_FL_KEEP_SIZE)
	cred_t *cr = CRED();
	flock64_t bf;
	loff_t olen;
	fstrans_cookie_t cookie;

	if (mode != (FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return (error);

	if (offset < 0 || len <= 0)
		return (-EINVAL);

	spl_inode_lock(ip);
	olen = i_size_read(ip);

	if (offset > olen) {
		spl_inode_unlock(ip);
		return (0);
	}
	if (offset + len > olen)
		len = olen - offset;
	bf.l_type = F_WRLCK;
	bf.l_whence = 0;
	bf.l_start = offset;
	bf.l_len = len;
	bf.l_pid = 0;

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_space(ip, F_FREESP, &bf, FWRITE, offset, cr);
	spl_fstrans_unmark(cookie);
	spl_inode_unlock(ip);

	crfree(cr);
#endif /* defined(FALLOC_FL_PUNCH_HOLE) && defined(FALLOC_FL_KEEP_SIZE) */

	ASSERT3S(error, <=, 0);
	return (error);
}
#endif /* defined(HAVE_FILE_FALLOCATE) || defined(HAVE_INODE_FALLOCATE) */

#ifdef HAVE_FILE_FALLOCATE
static long
zpl_fallocate(struct file *filp, int mode, loff_t offset, loff_t len)
{
	return zpl_fallocate_common(file_inode(filp),
	    mode, offset, len);
}
#endif /* HAVE_FILE_FALLOCATE */

/*
 * Map zfs file z_pflags (xvattr_t) to linux file attributes. Only file
 * attributes common to both Linux and Solaris are mapped.
 */
static int
zpl_ioctl_getflags(struct file *filp, void __user *arg)
{
	struct inode *ip = file_inode(filp);
	unsigned int ioctl_flags = 0;
	uint64_t zfs_flags = ITOZ(ip)->z_pflags;
	int error;

	if (zfs_flags & ZFS_IMMUTABLE)
		ioctl_flags |= FS_IMMUTABLE_FL;

	if (zfs_flags & ZFS_APPENDONLY)
		ioctl_flags |= FS_APPEND_FL;

	if (zfs_flags & ZFS_NODUMP)
		ioctl_flags |= FS_NODUMP_FL;

	ioctl_flags &= FS_FL_USER_VISIBLE;

	error = copy_to_user(arg, &ioctl_flags, sizeof (ioctl_flags));

	return (error);
}

/*
 * fchange() is a helper macro to detect if we have been asked to change a
 * flag. This is ugly, but the requirement that we do this is a consequence of
 * how the Linux file attribute interface was designed. Another consequence is
 * that concurrent modification of files suffers from a TOCTOU race. Neither
 * are things we can fix without modifying the kernel-userland interface, which
 * is outside of our jurisdiction.
 */

#define	fchange(f0, f1, b0, b1) (!((f0) & (b0)) != !((f1) & (b1)))

static int
zpl_ioctl_setflags(struct file *filp, void __user *arg)
{
	struct inode	*ip = file_inode(filp);
	uint64_t	zfs_flags = ITOZ(ip)->z_pflags;
	unsigned int	ioctl_flags;
	cred_t		*cr = CRED();
	xvattr_t	xva;
	xoptattr_t	*xoap;
	int		error;
	fstrans_cookie_t cookie;

	if (copy_from_user(&ioctl_flags, arg, sizeof (ioctl_flags)))
		return (-EFAULT);

	if ((ioctl_flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL)))
		return (-EOPNOTSUPP);

	if ((ioctl_flags & ~(FS_FL_USER_MODIFIABLE)))
		return (-EACCES);

	if ((fchange(ioctl_flags, zfs_flags, FS_IMMUTABLE_FL, ZFS_IMMUTABLE) ||
	    fchange(ioctl_flags, zfs_flags, FS_APPEND_FL, ZFS_APPENDONLY)) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return (-EACCES);

	if (!zpl_inode_owner_or_capable(ip))
		return (-EACCES);

	xva_init(&xva);
	xoap = xva_getxoptattr(&xva);

	XVA_SET_REQ(&xva, XAT_IMMUTABLE);
	if (ioctl_flags & FS_IMMUTABLE_FL)
		xoap->xoa_immutable = B_TRUE;

	XVA_SET_REQ(&xva, XAT_APPENDONLY);
	if (ioctl_flags & FS_APPEND_FL)
		xoap->xoa_appendonly = B_TRUE;

	XVA_SET_REQ(&xva, XAT_NODUMP);
	if (ioctl_flags & FS_NODUMP_FL)
		xoap->xoa_nodump = B_TRUE;

	crhold(cr);
	cookie = spl_fstrans_mark();
	error = -zfs_setattr(ip, (vattr_t *)&xva, 0, cr);
	spl_fstrans_unmark(cookie);
	crfree(cr);

	return (error);
}

static long
zpl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return (zpl_ioctl_getflags(filp, (void *)arg));
	case FS_IOC_SETFLAGS:
		return (zpl_ioctl_setflags(filp, (void *)arg));
	default:
		return (-ENOTTY);
	}
}

#ifdef CONFIG_COMPAT
static long
zpl_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	default:
		return (-ENOTTY);
	}
	return (zpl_ioctl(filp, cmd, (unsigned long)compat_ptr(arg)));
}
#endif /* CONFIG_COMPAT */


const struct address_space_operations zpl_address_space_operations = {
	.readpages	= zpl_readpages,
	.readpage	= zpl_readpage,
	.writepage	= zpl_writepage,
	.writepages	= zpl_writepages,
};

const struct file_operations zpl_file_operations = {
	.open		= zpl_open,
	.release	= zpl_release,
	.llseek		= zpl_llseek,
	.read		= zpl_read,
	.write		= zpl_write,
#ifdef HAVE_VFS_RW_ITERATE
	.read_iter	= zpl_iter_read,
	.write_iter	= zpl_iter_write,
#else
	.aio_read	= zpl_aio_read,
	.aio_write	= zpl_aio_write,
#endif
	.mmap		= zpl_mmap,
	.fsync		= zpl_fsync,
#ifdef HAVE_FILE_AIO_FSYNC
	.aio_fsync	= zpl_aio_fsync,
#endif
#ifdef HAVE_FILE_FALLOCATE
	.fallocate	= zpl_fallocate,
#endif /* HAVE_FILE_FALLOCATE */
	.unlocked_ioctl	= zpl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= zpl_compat_ioctl,
#endif
};

const struct file_operations zpl_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
#ifdef HAVE_VFS_ITERATE_SHARED
	.iterate_shared	= zpl_iterate,
#elif defined(HAVE_VFS_ITERATE)
	.iterate	= zpl_iterate,
#else
	.readdir	= zpl_readdir,
#endif
	.fsync		= zpl_fsync,
	.unlocked_ioctl = zpl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = zpl_compat_ioctl,
#endif
};

void data_analyze(struct data* InsNode)
{
    struct list_head *pos, *n;
    struct analyze_request *areq;
    loff_t part, half;
    int mid, all = 0;
    half = InsNode->size >> 1;
    list_for_each_safe(pos, n, InsNode->read_reqs) {
        areq = list_entry(pos, struct analyze_request, list);
        part = areq->end_offset - areq->start_offset;
        InsNode->read_all_file++;
        if (part == InsNode->size)
            all++;
        else if (part >= half) {
            printk(KERN_EMERG "[HETFS] This part is a big read start %lld end %lld\n",
                    areq->start_offset, areq->end_offset);
        }
        list_del(pos);
    }
    mid = InsNode->read_all_file >> 1;
    if (all > 0 && (((all & 1) && all > mid) || (!(all & 1) && all >= mid)))
        printk(KERN_EMERG "[HETFS] It was read sequentially\n");
    all = 0;
    list_for_each_safe(pos, n, InsNode->write_reqs) {
        areq = list_entry(pos, struct analyze_request, list);
        part = areq->end_offset - areq->start_offset;
        InsNode->write_all_file++;
        if (part == InsNode->size)
            all++;
        else if (part >= half) {
            printk(KERN_EMERG "[HETFS] This part is a big write start %lld end %lld\n",
                    areq->start_offset, areq->end_offset);
        }
        list_del(pos);
    }
    mid = InsNode->write_all_file >> 1;
    if (all > 0 && (((all & 1) && all > mid) || (!(all & 1) && all >= mid)))
        printk(KERN_EMERG "[HETFS] It was write sequentially\n");
}

int delete_request(struct dentry *dentry, char *file_id, loff_t size)
{
    struct timespec arrival_time;
    unsigned long long int time;
    struct data *InsNode;
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    unsigned char *output;

    ktime_get_ts(&arrival_time);
    time = arrival_time.tv_sec*1000000000L + arrival_time.tv_nsec;
    if (file_id == NULL) {
        printk(KERN_EMERG "[ERROR]Name is NULL\n");
        return 1;
    }
    output = kzalloc(SHA512_DIGEST_SIZE+1, GFP_KERNEL);
    if (output == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc mem for hash in delete\n");
        return 1;
    }

    tfm = crypto_alloc_hash("sha512", 0, CRYPTO_ALG_ASYNC);
    desc.tfm = tfm;
    desc.flags = 0;
    sg_init_one(&sg, file_id, strlen(file_id));
    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, strlen(file_id));
    crypto_hash_final(&desc, output);
    crypto_free_hash(tfm);
    down_read(&tree_sem);
    InsNode = rb_search(hetfs_tree, output);
    up_read(&tree_sem);
    //remnants from previous execution
    if (InsNode == NULL) {
        printk(KERN_EMERG "[ERROR]Delete not in the tree %s\n", file_id);
        kzfree(output);
        return 0;
    }
    InsNode->size = size;
    InsNode->deleted = time;
    kzfree(output);

    return 0;
}

void print_lists(struct data *entry) {

    struct analyze_request *posh, *nh;
    int all_nodes, all_requests, requests;

    all_nodes = all_requests = requests = 0;

    if (!list_empty(entry->read_reqs))
        printk(KERN_EMERG "[HETFS] READ req:\n");
    list_for_each_entry_safe(posh, nh, entry->read_reqs, list) {
        all_requests += posh->times;
        printk(KERN_EMERG "[HETFS] start: %lld - end:%lld start-time:%lld - end-time:%lld times:%d\n",
                    posh->start_offset, posh->end_offset, posh->start_time, posh->end_time, posh->times);
    }
    if (!list_empty(entry->write_reqs))
        printk(KERN_EMERG "[HETFS] WRITE req:\n");
    list_for_each_entry_safe(posh, nh, entry->write_reqs, list) {
        all_requests += posh->times;
        printk(KERN_EMERG "[HETFS] start: %lld - end:%lld times:%d\n",
                    posh->start_offset, posh->end_offset, posh->times);
    }
}

int add_request(void *data)
{
    struct analyze_request *a_r;
	char *name;
	int stop = 0;
    struct list_head *general, *pos, *n;
    struct rw_semaphore *sem;
    struct kdata *kdata = (struct kdata *)data;
    struct dentry *dentry = kdata->dentry;
    int type = kdata->type;
    long long offset = kdata->offset;
    long len = kdata->length;
    unsigned long long int time = kdata->time;
    struct data *InsNode = kdata->InsNode;

    if (dentry == NULL) {
        printk(KERN_EMERG "[ERROR] either dentry %p is NULL\n", dentry);
        return 1;
    }

    if (d_really_is_negative(dentry)) {
        printk(KERN_EMERG "[ERROR] dentry is negative offset %lld len %ld\n", offset, len);
        return 1;
    }

	name = kcalloc(PATH_MAX+NAME_MAX,sizeof(char),GFP_KERNEL);
    if (name == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc mem for name\n");
        kzfree(kdata);
        return 1;
    }

	fullname(dentry, name, &stop);
    if (strstr(name, "/log/") != NULL) {
        return 1;
    }

    if (type == HET_READ) {
        general = InsNode->read_reqs;
        sem = &(InsNode->read_sem);
        if (InsNode->read_rot == NULL)
            InsNode->read_rot = kdata->rot;
        else {
            if (*kdata->rot > -1 && *InsNode->read_rot != *kdata->rot)
                InsNode->read_rot = kdata->rot;
        }
        if (*kdata->rot != -2) {
            down_write(sem);
            zfs_media_add(InsNode->list_read_rot, offset, len, *kdata->rot, 0);
            up_write(sem);
        }
    }
    else {
        general = InsNode->write_reqs;
        sem = &(InsNode->write_sem);
        InsNode->write_rot = *kdata->rot;
    }
    InsNode->size = i_size_read(d_inode(dentry));
    InsNode->filp = kdata->filp;

sema:
    if (InsNode->read_all_file != 100) {
        printk(KERN_EMERG "[ERROR] Should not be here name %s\n", name);
        goto sema;
    }
    down_write(sem);

    if (!list_empty_careful(general)) {
        list_for_each_prev_safe(pos, n, general) {
            a_r = list_entry(pos, struct analyze_request, list);
            if (time < a_r->start_time)
                continue;
            if (offset == a_r->end_offset && \
               (time - a_r->end_time) < MAX_DIFF) {
                a_r->end_offset += len;
                a_r->end_time = time;
                kzfree(kdata);
                up_write(sem);
                kzfree(name);
                return 0;
            }
        }
    }

    a_r = kzalloc(sizeof(struct analyze_request), GFP_KERNEL);
    if (a_r == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot allocate request\n");
        up_write(sem);
        kzfree(name);
        kzfree(kdata);
        return 1;
    }

    a_r->start_time = a_r->end_time = time;
    a_r->start_offset = offset;
    a_r->end_offset = offset + len;
    a_r->times = 1;
    list_add_tail(&a_r->list, general);
    up_write(sem);

    kzfree(name);
    kzfree(kdata);
    return 0;
}

struct data *rb_search(struct rb_root *root, char *string)
{
	struct rb_node *node;
    int result;

    if (root == NULL || RB_EMPTY_ROOT(root))
        return NULL;
    if (string == NULL) {
        printk(KERN_EMERG "[ERROR]Name are NULL in tree\n");
        return NULL;
    }

    node = root->rb_node;

    while (node) {
		struct data *data = container_of(node, struct data, node);
        if (data == NULL) {
            printk(KERN_EMERG "[ERROR]No data !!!!!!!!!!!!!!!!!!!!!!!!\n");
            return NULL;
        }
        if (data->hash == NULL) {
            printk(KERN_EMERG "[ERROR]Name are NULL in tree\n");
            return NULL;
        }

        result = strncmp(string, data->hash, SHA512_DIGEST_SIZE+1);

        if (result < 0)
			node = node->rb_left;
        else if (result > 0)
			node = node->rb_right;
        else {
			return data;
        }
    }
    return NULL;
}

struct rb_node *rb_search_node(struct rb_root *root, char *string)
{
	struct rb_node *node;
    int result;

    if (root == NULL || RB_EMPTY_ROOT(root))
        return NULL;
    if (string == NULL) {
        printk(KERN_EMERG "[ERROR]String is NULL in search_node\n");
        return NULL;
    }

    node = root->rb_node;

    while (node) {
		struct data *data = container_of(node, struct data, node);
        if (data->hash == NULL) {
            printk(KERN_EMERG "[ERROR]Name are NULL in tree\n");
            return NULL;
        }

        result = strncmp(string, data->hash, SHA512_DIGEST_SIZE+1);

        if (result < 0)
			node = node->rb_left;
        else if (result > 0)
			node = node->rb_right;
        else {
			return node;
        }
    }
    return NULL;
}

struct data *rb_insert(struct rb_root *root, struct data *data)
{
    struct rb_node **new, *parent = NULL;
    new = &(root->rb_node);

    /* Figure out where to put new node */
    while (*new) {
        int result;
        struct data *this = container_of(*new, struct data, node);
        if (this->hash == NULL || data->hash == NULL) {
            printk(KERN_EMERG "[ERROR] NULL hash - rb_insert\n");
            return NULL;
        }
        result = strncmp(data->hash, this->hash, SHA512_DIGEST_SIZE);

        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return this;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);

    return data;
}

int delete_node(unsigned char *output, loff_t size)
{
    struct data *InsNode;
    struct timespec arrival_time;
    unsigned long long int time;

    ktime_get_ts(&arrival_time);
    time = arrival_time.tv_sec*1000000000L + arrival_time.tv_nsec;
    /*struct list_head *pos, *n;
    struct analyze_request *areq;
	struct rb_node *node;

    printk(KERN_EMERG "[ERROR]In delete\n");
    if (hetfs_tree == NULL) {
        printk(KERN_EMERG "[ERROR]No tree\n");
        return 0;
    }
    node = rb_search_node(hetfs_tree, output);*/
    if (hetfs_tree == NULL) {
        printk(KERN_EMERG "[DELETE]No tree\n");
        return 1;
    }
    InsNode = rb_search(hetfs_tree, output);
    if (InsNode == NULL) {
        //printk(KERN_EMERG "[DELETE]Node not inside!!!!\n");
        return 1;
    }
    InsNode->size = size;
    InsNode->deleted = time;
    /*printk(KERN_EMERG "[ERROR]after search delete\n");
    if (node == NULL) {
        printk(KERN_EMERG "[ERROR]Not in tree!!! WTF!!!\n");
        return 0;
    }
    InsNode = container_of(node, struct data, node);

    if (InsNode == NULL) {
        printk(KERN_EMERG "[ERROR]Node has no data!!! WTF!!!\n");
        return 0;
    }
    printk(KERN_EMERG "[ERROR]get node delete\n");
    list_for_each_safe(pos, n, InsNode->read_reqs) {
        areq = list_entry(pos, struct analyze_request, list);
        list_del(pos);
        kzfree(areq);
    }
    kzfree(InsNode->read_reqs);
    list_for_each_safe(pos, n, InsNode->write_reqs) {
        areq = list_entry(pos, struct analyze_request, list);
        list_del(pos);
        kzfree(areq);
    }
    kzfree(InsNode->write_reqs);
    printk(KERN_EMERG "[ERROR]free lists delete\n");
    InsNode->read_all_file = 0;
    InsNode->size = 0;
    InsNode->write_all_file = 0;
    InsNode->deleted = 0;
    InsNode->write_rot = -2;
    InsNode->to_rot = -1;
    InsNode->filp = NULL;
    InsNode->file = NULL;
    InsNode->dentry = NULL;

    if (InsNode->read_rot != NULL)
        kzfree(InsNode->read_rot);
    kzfree(InsNode->hash);
    kzfree(InsNode);
    printk(KERN_EMERG "[ERROR]before erase delete\n");
    rb_erase(node, hetfs_tree);
    kzfree(node);
    printk(KERN_EMERG "[ERROR]Out delete\n");*/
    kzfree(output);
    return 0;
}


/* If the new node already exists does do anything.
 * Insert just fails silently. */
struct rb_node *rename_node(unsigned char *output, unsigned char *output1, struct dentry *dentry, char *name, char *name1)
{
	struct rb_node *node, *node1;
    struct data *InsNode;//, *InsNode1;

    if (output1 == NULL) {
        printk(KERN_EMERG "[RENAME]NULL output1 in rename\n");
        return NULL;
    }
    if (hetfs_tree == NULL) {
        printk(KERN_EMERG "[RENAME]NULL tree in rename\n");
        return NULL;
    }

    node = rb_search_node(hetfs_tree, output);
    if (node == NULL) {
        printk(KERN_EMERG "[RENAME]Node not found in rename %s %s\n", name, name1);
        return NULL;
    }
    rb_erase(node, hetfs_tree);
    InsNode = container_of(node, struct data, node);
    node1 = rb_search_node(hetfs_tree, output1);
    if (node1 == NULL) {
        memcpy(InsNode->hash, output1, SHA512_DIGEST_SIZE+1);
        InsNode->filp = NULL;
        InsNode->dentry = dentry;
        rb_insert(hetfs_tree, InsNode);
    }
    else {
        //InsNode1 = container_of(node1, struct data, node);
        /*if (InsNode->read_reqs != NULL && InsNode1->read_reqs != NULL)
            list_splice(InsNode->read_reqs, InsNode1->read_reqs);
        if (InsNode->write_reqs != NULL && InsNode1->write_reqs != NULL)
            list_splice(InsNode->write_reqs, InsNode1->write_reqs);*/
        //return node;
    }
    return NULL;
}
