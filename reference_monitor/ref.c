#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

#define MODNAME "reference_monitor"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Implementazione di un Reference Monitor");

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

//apertura file di basso livello --> syscall do_filp_open
static int open_kernel_prehandler(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int) regs->di;
    const char *filename = ((struct filename *)(regs->si))->name;
    int flags = (int) regs->dx;
    //umode_t mode = (umode_t) regs->r10;

    //evito file in /run perché non interessano ed intasano il log di dmesg
    if(strncmp_custom(filename, "/run", 4) == 0) {
        return 0;
    }

    if(!(flags & O_WRONLY) && !(flags & O_RDWR) && !(flags & (O_EXCL | O_CREAT | O_TMPFILE))) {
        printk(KERN_INFO "Reference Monitor: open_kernel_prehandler: operazione concessa per filename: %s\n", filename);
        return 0;
    }

    printk(KERN_INFO "Reference Monitor: open_kernel_prehandler: filename: %s\n", filename);


    return 0;
}

//apertura file di alto livello --> syscall sys_openat2
static int openat_prehandler(struct kprobe *p, struct pt_regs *regs)
{
    int dfd = regs->di;
    struct filename *filename = (struct filename *)regs->si;
    const char *kernel_path = filename->name;
    int flags = regs->dx;
    umode_t mode = (umode_t) regs->r10;

    
    //char path[PATH_MAX];
    //long copied = strncpy_from_user(path, user_path, PATH_MAX);

    /* Ensure path is null-terminated in case of PATH_MAX length paths */
    /*path[PATH_MAX - 1] = '\0';

    if (copied > 0 || copied == -EFAULT) {
        if(strncmp_custom(path, "/run", 4) == 0) {
            return 0;
        }

        if (flags & O_CREAT || flags & O_WRONLY || flags & O_RDWR) {
            printk(KERN_INFO "File %s è stato creato o aperto in scrittura\n", path);
        }
    }

    return 0;*/

    if(strncmp(kernel_path, "/run", 4) == 0) {
        return 0;
    }

    if (flags & O_CREAT || flags & O_WRONLY || flags & O_RDWR) {
        printk(KERN_INFO "Reference Monitor: openat_prehandler: File %s è stato creato o aperto in scrittura\n", kernel_path);
    }

    return 0;
}

static struct kprobe kp_do_filp_open = {
    .pre_handler = open_kernel_prehandler,
    .symbol_name = "do_filp_open",
};

static struct kprobe kp_do_sys_openat = {
    .pre_handler = openat_prehandler,
    .symbol_name = "do_sys_openat",
};

int init_module(void) {
    int ret;

    ret = register_kprobe(&kp_do_filp_open);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to register do_filp_open kprobe, error %d\n", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: Kprobe do_filp_open registered successfully\n", MODNAME);
    
    ret = register_kprobe(&kp_do_sys_openat);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to register do_sys_openat kprobe, error %d\n", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: Kprobe do_sys_openat registered successfully\n", MODNAME);
    return 0;
}

void cleanup_module(void) {
    unregister_kprobe(&kp_do_filp_open);
    printk(KERN_INFO "%s: Kprobe do_filp_open unregistered\n", MODNAME);
    unregister_kprobe(&kp_do_sys_openat2);
    printk(KERN_INFO "%s: Kprobe do_sys_openat unregistered\n", MODNAME);
}

