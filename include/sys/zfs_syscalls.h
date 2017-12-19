void zfs_syscalls_initialize(void);

void list_print(struct list_head *dn);
struct zfs_syscalls {
    char *name;
    void (*test_fn)(void);
};
