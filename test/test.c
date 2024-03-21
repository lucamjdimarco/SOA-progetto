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

int get_absolute_path(int dfd, const char __user *filename, char *buffer) {
    struct path path;
    unsigned int lookup_flags = LOOKUP_FOLLOW; // Segue i link simbolici di default
    int error;

    buf_path = kmalloc(1024, GFP_KERNEL);
    if (!buf_path) {
        return -ENOMEM;
    }
    error = user_path_at(dfd, filename, lookup_flags, &path);
    if (error) {
        kfree(buf_path);
        return error;
    }
    
    //path = d_path(&path, buf_path, 1024);
    char *ret_ptr = d_path(&path, buf_path, 1024);
    if (IS_ERR(path)) {
        kfree(buf_path);
        return PTR_ERR(path);
    } else {
        strncpy(buffer, buf_path, 1024);
        buffer[1024 - 1] = '\0'; // Assicura la terminazione della stringa
        error = 0; // Successo
    }
    kfree(buf_path);

    path_put(&path);

    return error;
    


}


/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH];
    char absolute_path[PATH]; // Buffer per il percorso assoluto
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file

    unsigned int dfd = (unsigned int)regs->di;
    //manca il fatto che non recupera il path assoluto sempre
    //non ancora gestisco i flag

    

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }

        if(strncmp_custom(filename, "/run", 4) == 0) {
            return 0;
        }
        
        //printk(KERN_INFO "File Path: %s\n", path);
        if (get_absolute_path(dfd, filename, absolute_path) == 0) {
            printk(KERN_INFO "Absolute File Path: %s\n", absolute_path);
        } else {
            printk(KERN_INFO "Failed to get absolute path\n");
        }
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
