#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>

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

    unsigned int dfd = (unsigned int)regs->di;
    //manca il fatto che non recupera il path assoluto sempre
    //non ancora gestisco i flag

    struct file *file;
    struct path file_path;
    struct dentry *dentry;
    char *full_path;
    char *ret;
    

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }

        file = fget(dfd);
        if(!file) {
            printk(KERN_INFO "Failed to get file\n");
            return 0;
        }

        file_path = file->f_path;
        //dentry = file_path.dentry;
        ret = d_path(file_path, full_path, PATH);
        if(ret == NULL) {
            printk(KERN_INFO "Failed to get full path\n");
            return 0;
        }
        printk(KERN_INFO "Full Path: %s\n", full_path);



        /*if(strncmp_custom(filename, "/run", 4) == 0) {
            return 0;
        }


        
        printk(KERN_INFO "File Path: %s\n", path);*/
        
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
