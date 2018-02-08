#ifndef _ZFS_SYSCALLS
#define _ZFS_SYSCALLS

#ifndef _TREE_SEM
#define _TREE_SEM
static struct rw_semaphore tree_sem;
#endif

void zfs_syscalls_initialize(void);

void list_print(struct list_head *dn);
struct zfs_syscalls {
    char *name;
    void (*test_fn)(void);
};
#endif
