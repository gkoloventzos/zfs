#ifndef HETFS_H
#define HETFS_H

#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/types.h>

#define MAX_DIFF 200000000

struct rb_root hetfstree = RB_ROOT;

struct data {
	char *hash;
    char *file;
	loff_t size;
    int read_all_file;
    int write_all_file;
    unsigned long long int deleted;
    struct file *filp;
    struct analyze_request *read_reqs;
    struct analyze_request *write_reqs;
    struct rb_node node;
};

struct analyze_request {
	long long start_offset;
	long long end_offset;
	unsigned long long int start_time;
	unsigned long long int end_time;
    int times;
	struct list_head list;
};

struct data *search(struct rb_root *, char *);
int insert(struct rb_root *, struct data *);

#endif
