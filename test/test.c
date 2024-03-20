#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/fs.h>

#define PATH 256

static struct kprobe kp;

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

/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }

        if(strncmp_custom(filename, "/run", 4) == 0) {
            return 0;
        }

        if (kern_path(path, LOOKUP_FOLLOW, &path_struct)) {
            printk(KERN_INFO "Failed to get absolute path\n");
            return 0;
        }

        abs_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!abs_path) {
            printk(KERN_INFO "Failed to allocate memory for absolute path\n");
            return 0;
        }

        path_get(&path_struct);
        abs_path = d_path(&path_struct, abs_path, PATH_MAX);
        printk(KERN_INFO "Absolute File Path: %s\n", abs_path);
        kfree(abs_path);

        //printk(KERN_INFO "File Path: %s\n", path);
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
