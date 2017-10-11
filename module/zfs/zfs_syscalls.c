#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rbtree.h>
#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <sys/zfs_syscalls.h>
#include <sys/hetfs.h>
#include <sys/disk.h>
#include <asm/uaccess.h>
#include <linux/list.h>

#include <linux/crypto.h>
#include <crypto/sha.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

extern struct rb_root *hetfs_tree;
extern int media_tree;
extern int only_one;
extern int bla;
//extern int media_list;
extern char *only_name;
char *number;
char *procfs_buffer = NULL;
const char delimiters[] = " \n";

#define for_each_syscall(_iter, _tests, _tmp) \
	for (_tmp = 0, _iter = _tests; \
	     _tmp < ARRAY_SIZE(_tests); \
	     _tmp++, _iter++)

void print_media_tree(int flag) {
//    media_tree = flag;
    //media_list = flag;
    return;
}

void print_only_one(int flag) {
    only_one = flag;
}

void print_tree(int flag) {
    struct rb_node *node;
    struct data *entry;
    struct analyze_request *posh, *nh;
    int all_nodes, all_requests, requests;

    all_nodes = all_requests = requests = 0;

    down_read(&tree_sem);
    if (RB_EMPTY_ROOT(hetfs_tree)) {
        printk(KERN_EMERG "[ERROR] __exact empty root\n");
    }
    for (node = rb_first(hetfs_tree); node; node = rb_next(node)) {
        ++all_nodes;
        entry = rb_entry(node, struct data, node);
        printk(KERN_EMERG "[HETFS] file: %s\n", entry->dentry->d_name.name);
        if (flag) {
            if (!list_empty(entry->read_reqs) && flag)
                printk(KERN_EMERG "[HETFS] READ req:\n");
            list_for_each_entry_safe(posh, nh, entry->read_reqs, list) {
                all_requests += posh->times;
                printk(KERN_EMERG "[HETFS] start: %lld - end:%lld times:%d\n",
                            posh->start_offset, posh->end_offset, posh->times);
            }
            if (!list_empty(entry->write_reqs))
                printk(KERN_EMERG "[HETFS] WRITE req:\n");
            list_for_each_entry_safe(posh, nh, entry->write_reqs, list) {
                all_requests += posh->times;
                printk(KERN_EMERG "[HETFS] start: %lld - end:%lld times:%d\n",
                            posh->start_offset, posh->end_offset, posh->times);
            }
        }
    }
    if (flag)
        printk(KERN_EMERG "[HETFS]Tree Nodes:%d, requests:%d\n", all_nodes, all_requests);
    else
        printk(KERN_EMERG "[HETFS]Tree Nodes:%d\n", all_nodes);

    up_read(&tree_sem);
}

static void print_nodes(void)
{
    print_tree(false);
}

static void print_all(void)
{
    print_tree(true);
}

static void print_medium(void)
{
    print_media_tree(true);
}

static void print_list(void)
{
    printk(KERN_EMERG "[HETFS]Searching for %s\n", only_name);
    bla=1;
    print_only_one(1);
}

static void stop_print_list(void) {
    kfree(procfs_buffer);
    only_name = NULL;
    print_only_one(0);
}

static void stop_print_medium(void)
{
    print_media_tree(false);
}

static void change_medium(void)
{
    unsigned char *output;
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    struct data *tree_entry = NULL;

    output = kzalloc(SHA512_DIGEST_SIZE+1, GFP_KERNEL);
    if (output == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc memory for output\n");
        return;
    }

    tfm = crypto_alloc_hash("sha512", 0, CRYPTO_ALG_ASYNC);
    desc.tfm = tfm;
    desc.flags = 0;
    sg_init_one(&sg, only_name, strlen(only_name));
    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, strlen(only_name));
    crypto_hash_final(&desc, output);
    crypto_free_hash(tfm);
    tree_entry = rb_search(hetfs_tree, output);
    if (tree_entry == NULL) {
        printk(KERN_EMERG "[ERROR] No node in tree\n");
        kzfree(output);
        return;
    }

    /* You have read where the medium is stored and changed it */
    if (tree_entry->read_rot == NULL) {
        printk(KERN_EMERG "[ERROR] Not changed read_rot because it is NULL\n");
        kzfree(output);
        return;
    }
    if (*tree_entry->read_rot == METASLAB_ROTOR_VDEV_TYPE_HDD) {
        tree_entry->write_rot = METASLAB_ROTOR_VDEV_TYPE_SSD;
    }
    else if (*tree_entry->read_rot == METASLAB_ROTOR_VDEV_TYPE_SSD) {
        tree_entry->write_rot = METASLAB_ROTOR_VDEV_TYPE_HDD;
    }
    else {
        printk(KERN_EMERG "[ERROR] Not changed read_rot %d\n", *tree_entry->read_rot);
    }
    kzfree(output);
    return;
}

static void print_media(void)
{
    unsigned char *output;
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    struct data *tree_entry = NULL;

    output = kzalloc(SHA512_DIGEST_SIZE+1, GFP_KERNEL);
    if (output == NULL) {
        printk(KERN_EMERG "[ERROR] Cannot alloc memory for output\n");
        return;
    }

    tfm = crypto_alloc_hash("sha512", 0, CRYPTO_ALG_ASYNC);
    desc.tfm = tfm;
    desc.flags = 0;
    sg_init_one(&sg, only_name, strlen(only_name));
    crypto_hash_init(&desc);
    crypto_hash_update(&desc, &sg, strlen(only_name));
    crypto_hash_final(&desc, output);
    crypto_free_hash(tfm);
    tree_entry = rb_search(hetfs_tree, output);
    if (tree_entry == NULL) {
        printk(KERN_EMERG "[ERROR] No node in tree\n");
        kzfree(output);
        return;
    }

    if (tree_entry->write_rot == METASLAB_ROTOR_VDEV_TYPE_HDD)
        printk(KERN_EMERG "[PRINT] File %s dn_write_rot METASLAB_ROTOR_VDEV_TYPE_HDD\n", only_name);
    else if (tree_entry->write_rot == METASLAB_ROTOR_VDEV_TYPE_SSD)
        printk(KERN_EMERG "[PRINT] File %s dn_write_rot METASLAB_ROTOR_VDEV_TYPE_SSD\n", only_name);
    else if (tree_entry->write_rot == -1)
        printk(KERN_EMERG "[PRINT] File %s dn_write_rot METASLAB_ROTOR_VDEV_TYPE_HDD with -1\n", only_name);
    else
        printk(KERN_EMERG "[PRINT] File %s dn_write_rot %d\n", only_name, tree_entry->write_rot);

    if (tree_entry->read_rot != NULL) {
        if (*tree_entry->read_rot == METASLAB_ROTOR_VDEV_TYPE_HDD)
            printk(KERN_EMERG "[PRINT] File %s dn_read_rot METASLAB_ROTOR_VDEV_TYPE_HDD\n", only_name);
        else if (*tree_entry->read_rot == METASLAB_ROTOR_VDEV_TYPE_SSD)
            printk(KERN_EMERG "[PRINT] File %s dn_read_rot METASLAB_ROTOR_VDEV_TYPE_SSD\n", only_name);
        else
            printk(KERN_EMERG "[PRINT] File %s dn_read_rot %d\n", only_name, *tree_entry->read_rot);
    }
    else {
        printk(KERN_EMERG "[PRINT] File %s dn_read_rot is NULL\n", only_name);
    }

    kzfree(output);
    return;
}

struct list_head *zip_list(struct list_head *general)
{
    struct list_head *pos, *n, *pos1, *new;
    struct analyze_request *areq, *areq1;
    int found;

    new = kzalloc(sizeof(struct list_head), GFP_KERNEL);
    if (new == NULL)
        return NULL;
    INIT_LIST_HEAD(new);

    list_for_each_safe(pos, n, general) {
        found = 0;
        areq = list_entry(pos, struct analyze_request, list);
        list_for_each(pos1, new){
            areq1 = list_entry(pos1, struct analyze_request, list);
            if (areq->start_offset == areq1->start_offset &&
                areq->end_offset == areq1->end_offset) {
                areq1->times += areq->times;
                found = 1;
                break;
            }
        }
        if (!found) {
            __list_del_entry(pos);
            list_add_tail(pos,new);
        }
    }
    list_for_each_safe(pos, n, general) {
        areq = list_entry(pos, struct analyze_request, list);
        list_del(pos);
        kzfree(areq);
    }
    kzfree(general);
    return new;
}

void analyze(struct data* InsNode)
{
    struct list_head *pos, *n;
    struct analyze_request *areq;
    loff_t part, half;
    int mid, all = 0;
    half = InsNode->size >> 1;
    if (!list_empty(InsNode->read_reqs)) {
        InsNode->to_rot = 0;
        InsNode->read_reqs = zip_list(InsNode->read_reqs);
        printk(KERN_EMERG "[HETFS]File %s\n", InsNode->file);
        list_for_each_safe(pos, n, InsNode->read_reqs) {
            areq = list_entry(pos, struct analyze_request, list);
            part = areq->end_offset - areq->start_offset;
            InsNode->read_all_file += areq->times;
            if (part == InsNode->size) {
                all += areq->times;
            }
            else if (part >= half) {
                printk(KERN_EMERG "[HETFS] This part is a big read start %lld end %lld accessed %d times\n",
                        areq->start_offset, areq->end_offset, areq->times);
            }
        }
        mid = InsNode->read_all_file >> 1;
        if (all > 0 && (((all & 1) && all > mid) || (!(all & 1) && all >= mid))) {
            InsNode->to_rot |= METASLAB_ROTOR_VDEV_TYPE_HDD;
            printk(KERN_EMERG "[HETFS] It was read sequentially\n");
        }
        else {
            InsNode->to_rot |= METASLAB_ROTOR_VDEV_TYPE_SSD;
        }
    }
    if (!list_empty(InsNode->write_reqs)) {
        InsNode->write_reqs = zip_list(InsNode->write_reqs);
        all = 0;
        list_for_each_safe(pos, n, InsNode->write_reqs) {
            areq = list_entry(pos, struct analyze_request, list);
            part = areq->end_offset - areq->start_offset;
            InsNode->write_all_file += areq->times;
            if (part == InsNode->size)
                all++;
            else if (part >= half) {
                printk(KERN_EMERG "[HETFS] This part is a big write start %lld end %lld accessed %d times\n",
                        areq->start_offset, areq->end_offset, areq->times);
            }
        }
        mid = InsNode->write_all_file >> 1;
        if (all > 0 && (((all & 1) && all > mid) || (!(all & 1) && all >= mid)))
            printk(KERN_EMERG "[HETFS] It was write sequentially\n");
    }
}

static void analyze_tree(void)
{

    struct rb_node *node;
    struct data *entry;
    printk(KERN_EMERG "[HETFS]Start of analyze\n");
    down_read(&tree_sem);
    /*We actually write to nodes in the tree but no insert or delete*/
    for (node = rb_first(hetfs_tree); node; node = rb_next(node)) {
        entry = rb_entry(node, struct data, node);
        analyze(entry);
    }
    up_read(&tree_sem);
    printk(KERN_EMERG "[HETFS] End of analyze\n");

}

struct zfs_syscalls available_syscalls[] = {
	{ "print_nodes",	print_nodes	},
	{ "print_all",		print_all	},
	{ "analyze_tree",	analyze_tree	},
	{ "print_medium",	print_medium	},
	{ "stop_print_medium",		stop_print_medium	},
	{ "print_list",	    print_list	},
	{ "stop_print_list",		stop_print_list	},
	{ "change_medium",	change_medium	},
	{ "print_media",	print_media	},
};

static void run_syscall(struct zfs_syscalls *syscall)
{
    syscall->test_fn();
}

static int zfs_syscalls_run(unsigned long op)
{
    struct zfs_syscalls *syscall;

    if (op > ARRAY_SIZE(available_syscalls))
        return -EINVAL;

    syscall = &available_syscalls[op];
    run_syscall(syscall);

    return 0;
}

static int syscall_proc_show(struct seq_file *m, void *v)
{
	int i;
	struct zfs_syscalls *syscall;

	seq_printf(m, "Usage: echo <syscall_idx> > /proc/zfs_syscalls\n\n");
	seq_printf(m, "Test Idx    Syscall Name\n");
	seq_printf(m, "---------------------\n");
	for_each_syscall(syscall, available_syscalls, i) {
		seq_printf(m, "     %3d    %s\n", i, syscall->name);
	}

	return 0;
};

static ssize_t __zfs_syscall_write(struct file *file, const char __user *buffer,
                            size_t count, loff_t *pos)
{
    int ret;
    unsigned long val;
    procfs_buffer = kzalloc(strlen(buffer)+2, GFP_KERNEL);
    procfs_buffer[strlen(buffer)+1] = ' ';

    if ( copy_from_user(procfs_buffer, buffer, 2048) ) {
            return -EFAULT;
    }

/*    ret = kstrtoul_from_user(buffer, count, 10, &val);
    if (ret)
        return ret;*/
    number = strsep(&procfs_buffer, delimiters);
    ret = kstrtoul(number, 10, &val);
    if (ret)
        return ret;
    only_name = strsep(&procfs_buffer, delimiters);
    strsep(&procfs_buffer, delimiters);
    ret = zfs_syscalls_run(val);
    if (ret)
        return ret;

    *pos += count;

    return ret ? ret : count;
}

static ssize_t zfs_syscall_write(struct file *file, const char __user *buffer,
                            size_t count, loff_t *pos)
{
    return __zfs_syscall_write(file, buffer, count, pos);
}

static int zfs_syscall_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_proc_show, NULL);
}

static const struct file_operations zfs_syscalls_proc_fops = {
    .owner = THIS_MODULE,
    .open = zfs_syscall_proc_open,
    .read = seq_read,
    .write = zfs_syscall_write,
};

static int __init zfs_syscalls_init(void)
{

	proc_create("zfs_syscalls", 0, NULL, &zfs_syscalls_proc_fops);
	pr_info("&zfs_syscalls_proc_fops successfully initialized\n");
	return 0;
}

void zfs_syscalls_initialize(void)
{
    zfs_syscalls_init();
}

//__initcall(zfs_syscalls_init);
//module_init(zfs_syscalls_init);
