#ifndef _SYS_HETFS_H
#define _SYS_HETFS_H

#ifdef _KERNEL
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <sys/dnode.h>
#endif

#define MAX_DIFF 200000000
#define MAX_NAME 255
#define HET_READ 0
#define HET_WRITE 1

/*
 * Five categories, from faster to slower:
 *
 * nonrot (SSD)      disk or mirror
 * nonrot (SSD)      raidz
 * mixed nonrot+rot  anything (raidz makes little sense)
 * rot (HDD)         disk or mirror
 * rot (HDD)         raidz
 */

#define	METASLAB_ROTOR_VDEV_TYPE_SSD		0x01
#define	METASLAB_ROTOR_VDEV_TYPE_SSD_RAIDZ	0x02
#define	METASLAB_ROTOR_VDEV_TYPE_MIXED		0x04
#define	METASLAB_ROTOR_VDEV_TYPE_HDD		0x08
#define	METASLAB_ROTOR_VDEV_TYPE_HDD_RAIDZ	0x10

#define filp2name(filp) filp->f_path.dentry->d_name.name

#ifdef _KERNEL
static DECLARE_RWSEM(tree_sem);

struct analyze_request {
    long long start_offset;
    long long end_offset;
    unsigned long long int start_time;
    unsigned long long int end_time;
    int times;
    struct list_head list;
};

struct data {
	char *hash;
    char *file;
	loff_t size;
    int8_t read_all_file;
    int8_t write_all_file;
    int8_t read_seq;
    int8_t write_seq;
    int8_t to_rot;
    int8_t write_rot;
    int8_t read_rot;
    unsigned long long int deleted;
    struct list_head *read_reqs;
    struct list_head *write_reqs;
    struct rw_semaphore read_sem;
    struct rw_semaphore write_sem;
    struct dentry *dentry;
    struct rb_node node;
};

struct kdata {
    struct dentry *dentry;
    int8_t rot;
    loff_t offset;
    long length;
    int type;
    unsigned long long int time;
};

struct data *rb_search(struct rb_root *, char *);
int rb_insert(struct rb_root *, struct data *);
int add_request(void *);
#endif
#endif
