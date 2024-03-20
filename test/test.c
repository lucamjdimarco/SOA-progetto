#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define PATH_MAX 256

static struct kprobe kp;

/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH_MAX];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file

    if (filename) {
        if (strncpy_from_user(path, filename, PATH_MAX) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }
        printk(KERN_INFO "File Path: %s\n", path);
    } else {
        printk(KERN_INFO "No filename provided\n");
    }
    return 0;
}

static int __init kprobe_init(void) {
    kp.pre_handler = handler_pre;
    kp.symbol_name = "do_sys_openat2"; // Nome della funzione da intercettare

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
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Kprobe example");
