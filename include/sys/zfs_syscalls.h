void zfs_syscalls_initialize(void);

void list_print(struct list_head *dn);
struct list_head *tight_list(struct list_head *);
struct zfs_syscalls {
    char *name;
    void (*test_fn)(void);
};
