#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>  // for spin_lock, spin_unlock
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/syscalls.h>

MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Aux function for the reference monitor");
MODULE_LICENSE("GPL");


int strncmp_custom(const char *s1, const char *s2, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    return 0;
}

char *get_absolute_path(const char __user *filename) {
    struct path path;
    int dfd = AT_FDCWD;
    char *ret_ptr = NULL;
    int error = -EINVAL;
    int flag = 0;
    unsigned int lookup_flags = 0;
    char *tpath = kmalloc(1024, GFP_KERNEL);

    if (!(flag & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

    error = user_path_at(dfd, filename, lookup_flags, &path);
    if (error) {
        goto out;
     }

    ret_ptr = d_path(&path, tpath, 1024);
    //printk("%s\n", ret_ptr);
    kfree(tpath);
    return ret_ptr;

out:
    kfree(tpath);
    return NULL;
}