void zfs_syscalls_initialize(void);

struct zfs_syscalls {
    char *name;
    void (*test_fn)(void);
};
