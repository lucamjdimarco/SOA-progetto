#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
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

#define PATH 512

//krpobe struct
static struct kprobe kp_openat2;
static struct kprobe kp_filp_open;

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





static int handler_openat2(struct kprobe *p, struct pt_regs *regs) {
    char path[PATH];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file
    //int fd = (int)(regs->di);
    struct open_how *how = (struct open_how *)regs->dx;
    char *ret_ptr = NULL;

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            //printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }
        
        if(strncmp_custom(path, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path, "/", 1) != 0) {
            ret_ptr = get_absolute_path(filename);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path: %s\n", path);
        }
        
        if ((how->flags & O_WRONLY) || (how->flags & O_CREAT) || (how->flags & O_TRUNC) || (how->flags & O_APPEND) || (how->flags & O_RDWR)) {
            printk(KERN_INFO "File opened in write mode.\n");
        }
        
    } else {
        printk(KERN_INFO "No filename provided\n");
    }




    return 0;
}

static int handler_filp_open(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;
    //struct filename *filename = (struct filename *)regs->si;
    const struct open_flags *op = (const struct open_flags *)regs->dx;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    if(path_user == NULL) {
        printk(KERN_INFO "No path user provided\n");
        return 0;
    
    } else {
        printk(KERN_INFO "Path user: %s\n", path_user);
    }
    if(path_kernel == NULL) {
        printk(KERN_INFO "No path kernel provided\n");
        return 0;
    } else {
        printk(KERN_INFO "Path kernel: %s\n", path_kernel);
    
    }


}

static int __init kprobe_init(void) {
    kp_openat2.pre_handler = handler_openat2;
    kp_openat2.symbol_name = "do_sys_openat2"; // Nome della funzione da intercettare

    kp_filp_open.pre_handler = handler_filp_open;
    kp_filp_open.symbol_name = "do_filp_open";

    if (register_kprobe(&kp_openat2) < 0) {
        printk(KERN_INFO "Failed to register kprobe openat2\n");
        return -1;
    }
    if (register_kprobe(&kp_filp_open) < 0) {
        printk(KERN_INFO "Failed to register kprobe filp_open\n");
        return -1;
    }
    printk(KERN_INFO "Kprobe openat2 registered successfully\n");
    printk(KERN_INFO "Kprobe filp_open registered successfully\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp_openat2);
    unregister_kprobe(&kp_filp_open);
    printk(KERN_INFO "Kprobe openat2 unregistered\n");
    printk(KERN_INFO "Kprobe filp_open unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Kprobe example");
