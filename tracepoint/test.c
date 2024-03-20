#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <linux/fcntl.h>
#include <linux/filename.h>

void probe_sys_enter_openat2(void *data, struct pt_regs *regs, long id)
{
    int dfd = regs->di;
    const char __user *filename = (const char __user *)regs->si;
    struct open_how *how = (struct open_how *)regs->dx;

    int flags = how->flags;

    if (flags & O_CREAT || flags & O_WRONLY || flags & O_RDWR) {
        printk(KERN_INFO "Reference Monitor: open_prehandler: File %s è stato creato o aperto in scrittura\n", filename);
    }
}

int init_module(void)
{
    int ret;

    ret = register_tracepoint_probe("syscalls", "sys_enter_openat2", probe_sys_enter_openat2, NULL);
    if (ret) {
        printk(KERN_INFO "Failed to register tracepoint probe: %d\n", ret);
        return ret;
    }

    return 0;
}

void cleanup_module(void)
{
    unregister_tracepoint_probe("syscalls", "sys_enter_openat2", probe_sys_enter_openat2, NULL);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Test con tracepoint");