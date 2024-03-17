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

//apertura file nello space kernerl --> syscall do_filp_open
static int open_kernel_prehandler(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int) regs->di;
    const char *filename = ((struct filename *)(regs->si))->name;
    int flags = (int) regs->dx;
    //umode_t mode = (umode_t) regs->r10;

    //evito file in /run perché non interessano ed intasano il log di dmesg
    if(strncmp_custom(filename, "/run", 4) == 0) {
        return 0;
    }

    if(!(flags & O_CREAT) || !(flags & O_WRONLY) || !(flags & O_RDWR) || !(flags(O_EXCL))) {
        return 0;
    }
    
    printk(KERN_INFO "Reference Monitor: open_kernel_prehandler: filename: %s\n", filename);


    return 0;
}

static struct kprobe kp = {
    .pre_handler = open_kernel_prehandler,
    .symbol_name = "do_filp_open",
};

int init_module(void) {
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "%s: Failed to register kprobe, error %d\n", MODNAME, ret);
        return ret;
    }
    printk(KERN_INFO "%s: Kprobe registered successfully\n", MODNAME);
    return 0;
}

void cleanup_module(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "%s: Kprobe unregistered\n", MODNAME);
}

