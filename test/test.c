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

#define PATH 512

//krpobe struct
static struct kprobe kp_openat2;
static struct kprobe kp_filp_open;
static struct kprobe kp_rmdir;
static struct kprobe kp_mkdir_at;
static struct kprobe kp_unlinkat;

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
};

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

        if ((how->flags & O_WRONLY) || (how->flags & O_CREAT) || (how->flags & O_TRUNC) || (how->flags & O_APPEND) || (how->flags & O_RDWR)) {
            if(strncmp_custom(path, "/", 1) != 0) {
                ret_ptr = get_absolute_path(filename);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path openat2\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path openat2: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path openat2: %s\n", path);
            }
        }
        
        /*if ((how->flags & O_WRONLY) || (how->flags & O_CREAT) || (how->flags & O_TRUNC) || (how->flags & O_APPEND) || (how->flags & O_RDWR)) {
            printk(KERN_INFO "File opened in write mode.\n");
        }*/
        
    } else {
        printk(KERN_INFO "No filename provided\n");
    }




    return 0;
}

static int handler_filp_open(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;
    //struct filename *filename = (struct filename *)regs->si;
    struct open_flags *op = (struct open_flags *)(regs->dx);
    //int flag = op->open_flag;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    if ((op->open_flag & O_WRONLY) || (op->open_flag & O_CREAT) || (op->open_flag & O_TRUNC) || (op->open_flag & O_APPEND) || (op->open_flag & O_RDWR)) {
            //printk(KERN_INFO "File opened in write mode.\n");
        if(path_user == NULL){
            //uso path kernel 
            if(strncmp_custom(path_kernel, "/run", 4) == 0) {
                return 0;
            }

            if(strncmp_custom(path_kernel, "/", 1) != 0) {
                ret_ptr = get_absolute_path(path_kernel);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path do_filp_open\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path do_filp_open: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path do_filp_open: %s\n", path_kernel);
            }

        } else {
            //uso path user
            if(strncmp_custom(path_user, "/run", 4) == 0) {
                return 0;
            }

            if(strncmp_custom(path_user, "/", 1) != 0) {
                ret_ptr = get_absolute_path(path_user);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path do_filp_open\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path do_filp_open: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path do_filp_open: %s\n", path_user);
            }
        }
    } else {
        return 0;
    }
    return 0;
}

static int handler_rmdir(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path rmdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path rmdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path rmdir: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path rmdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path rmdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path rmdir: %s\n", path_user);
        }
    }
    
    return 0;
}

static int handler_mkdirat(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    
    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path mkdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path mkdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path mkdir: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path mkdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path mkdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path mkdir: %s\n", path_user);
        }
    }
    
    return 0;
}

static int handler_unlinkat(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    
    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path unlinkat\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path unlinkat: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path unlinkat: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path unlinkat\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path unlinkat: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path unlinkat: %s\n", path_user);
        }
    }
    
    return 0;
}

static int __init kprobe_init(void) {
    kp_openat2.pre_handler = handler_openat2;
    kp_openat2.symbol_name = "do_sys_openat2"; // Nome della funzione da intercettare

    kp_filp_open.pre_handler = handler_filp_open;
    kp_filp_open.symbol_name = "do_filp_open";

    kp_rmdir.pre_handler = handler_rmdir;
    kp_rmdir.symbol_name = "do_rmdir";

    kp_mkdir_at.pre_handler = handler_mkdirat;
    kp_mkdir_at.symbol_name = "do_mkdirat";

    kp_unlinkat.pre_handler = handler_unlinkat;
    kp_unlinkat.symbol_name = "do_unlinkat";


    if (register_kprobe(&kp_openat2) < 0) {
        printk(KERN_INFO "Failed to register kprobe openat2\n");
        return -1;
    }
    if (register_kprobe(&kp_filp_open) < 0) {
        printk(KERN_INFO "Failed to register kprobe filp_open\n");
        return -1;
    }
    if (register_kprobe(&kp_rmdir) < 0) {
        printk(KERN_INFO "Failed to register kprobe rmdir\n");
        return -1;
    }
    if (register_kprobe(&kp_mkdir_at) < 0) {
        printk(KERN_INFO "Failed to register kprobe mkdirat\n");
        return -1;
    }
    if(register_kprobe(&kp_unlinkat) < 0) {
        printk(KERN_INFO "Failed to register kprobe unlinkat\n");
        return -1;
    }
    printk(KERN_INFO "Kprobe openat2 registered successfully\n");
    printk(KERN_INFO "Kprobe filp_open registered successfully\n");
    printk(KERN_INFO "Kprobe rmdir registered successfully\n");
    printk(KERN_INFO "Kprobe mkdirat registered successfully\n");
    printk(KERN_INFO "Kprobe unlinkat registered successfully\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp_openat2);
    unregister_kprobe(&kp_filp_open);
    unregister_kprobe(&kp_rmdir);
    unregister_kprobe(&kp_mkdir_at);
    unregister_kprobe(&kp_unlinkat);
    printk(KERN_INFO "Kprobe openat2 unregistered\n");
    printk(KERN_INFO "Kprobe filp_open unregistered\n");
    printk(KERN_INFO "Kprobe rmdir unregistered\n");
    printk(KERN_INFO "Kprobe mkdirat unregistered\n");
    printk(KERN_INFO "Kprobe unlinkat unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Kprobe example");