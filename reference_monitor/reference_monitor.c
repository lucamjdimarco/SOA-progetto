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

//apertura file nello space kernerl --> syscall do_filp_open
static int open_kernel_prehandler(struct kprobe *p, struct pt_regs *regs) {
    
    int fd = (int) regs->di;
    const char *filename = ((struct filename *)(regs->si))->name;
    struct open_flags *op_flags = (struct open_flags *)(regs->dx);
    int flags = op_flags->open_flag;
    unsigned short mode = op_flags->mode;

    //evito file in /run perché non interessano ed intasano il log di dmesg
    if(strcmp(filename, "/run") == 0) {
        return 0;
    }

    printk(KERN_INFO "Reference Monitor: open_kernel_prehandler: filename: %s, flags: %d, mode: %d\n", filename, flags, mode);

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

