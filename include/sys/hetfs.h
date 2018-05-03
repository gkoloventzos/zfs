#ifndef _SYS_HETFS_H
#define _SYS_HETFS_H

#ifdef _KERNEL
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <sys/dnode.h>
//#include <sys/zfs_media.h>
#endif

#define MAX_DIFF 4000000000
#define MAX_NAME 255
#define HET_READ 0
#define HET_WRITE 1
#define HET_MMAP 2
#define HET_RMAP 3

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

#define sysbench(x) (strlen(x) == 17 && strncmp(x, "/usr/bin/sysbench", 17) == 0)
#define mysql_check(x) (strlen(x) == 14 && strncmp(x, "/usr/bin/mysql", 14) == 0)
#define mysqld_check(x) (strlen(x) == 16 && strncmp(x, "/usr/sbin/mysqld", 16) == 0)
#define mysql(x) (strstr(x, "/ibdata") != NULL ||\
        strstr(x, "ib_logfile") != NULL || strstr(x, "sbtest.ibd") != NULL ||\
        mysql_check(x) || mysqld_check(x) || sysbench(x))

#define kvm(x) (strstr(x, "/var/kvm/images/cadmus.img") || \
                strstr(x, "/var/kvm/images/ssd.img") || \
                strstr(x, "/var/kvm/images/blocks.img"))

#define file_check(x) kvm(x)

#ifdef _KERNEL

struct storage_media {
    char *name;
    int bit;
};

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
	char *hash;             //Should NEVER be NULL
    char *file;
	loff_t size;
    bool print;
    int8_t read_all_file;
    int8_t write_all_file;
    int8_t read_seq;
    int8_t write_seq;
	uint32_t dn_datablksz;		/* in bytes */
    uint8_t dn_datablkshift;
    unsigned long long int deleted;
    struct list_head *read_reqs;
    struct list_head *write_reqs;
    struct list_head *mmap_reqs;
    struct list_head *rmap_reqs;
    struct list_head *list_write_rot;
    struct list_head *list_read_rot;
    struct rw_semaphore read_sem;
    struct rw_semaphore write_sem;
    struct dentry *dentry;  //Mainly never NULL
    struct file *filp;      //It can be NULL in case of rename
    struct rb_node node;
};

struct kdata {
    struct dentry *dentry;
    struct file *filp;
    struct list_head *list_rot;
    loff_t offset;
    long length;
    int type;
	loff_t size;
    unsigned long long int time;
    struct data *InsNode;
};

struct data *rb_search(struct rb_root *, char *);
struct data *rb_insert(struct rb_root *, struct data *);
int add_request(void *);
void fullname(struct dentry *, char *, int *);
int delete_node(unsigned char *, loff_t);
struct rb_node *rename_node(unsigned char *, unsigned char *, struct dentry *, char *, char *);
struct data *tree_insearch(struct dentry *dentry, char *);
#endif
#endif
