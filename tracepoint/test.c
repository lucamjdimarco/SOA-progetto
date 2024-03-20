#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *task = current;
    printk(KERN_INFO "Intercepted sys_enter_openat2\n");

    // Otteniamo i dati dai registri
    unsigned int dfd = regs->di;  // file descriptor
    const char __user *filename = (const char __user *)regs->si;  // path del file
    int flags = regs->dx;  // flag di apertura

    // Leggiamo il path del file dall'utente
    char path[PATH_MAX];
    if (copy_from_user(path, filename, PATH_MAX) != 0) {
        printk(KERN_INFO "Failed to copy filename from user space\n");
        return 0;
    }
    
    printk(KERN_INFO "File Descriptor: %u\n", dfd);
    printk(KERN_INFO "File Path: %s\n", path);
    printk(KERN_INFO "Flags: %d\n", flags);
    
    return 0;
}

static struct tracepoint *tp;

static int __init kprobe_init(void) {
    tp = tracepoint_ptr("syscalls:sys_enter_openat2");
    if (!tp) {
        printk(KERN_INFO "Failed to find tracepoint\n");
        return -1;
    }

    kp.pre_handler = handler_pre;
    kp.symbol_name = NULL; // Non è necessario specificare il nome della funzione

    if (register_kprobe(&kp) < 0) {
        printk(KERN_INFO "Failed to register kprobe\n");
        return -1;
    }
    printk(KERN_INFO "Kprobe registered successfully\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
