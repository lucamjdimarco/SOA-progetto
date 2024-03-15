#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/namei.h>


#define MODNAME "openat_handler"
#define MAX_PATH_LENGTH 256

static int openat_pre_handler(struct kprobe *ri, struct pt_regs *regs) {

    const __user char *user_path = (const __user char *)(regs->si);
    
    char kernel_path[MAX_PATH_LENGTH];
    if (copy_from_user(kernel_path, user_path, MAX_PATH_LENGTH) != 0) {
        // Errore nella copia dalla stringa utente
        return -EFAULT;
    }
    
    if (strcmp("/home/luca/Documenti/test", kernel_path) == 0) {
            printk("%s: Tentativo di creare il file %s in una directory protetta.\n", MODNAME, kernel_path);
    } 
    
    //printk(KERN_INFO "Percorso completo del file: %s\n", kernel_path);

    /*if (flags & O_CREAT) {
        char *file_path = kmalloc(MAX_PATH_LENGTH, GFP_KERNEL);
        if (file_path == NULL) {
            printk(KERN_ERR "Impossibile allocare memoria per file_path\n");
            if (path != NULL) kfree(path);
            return -ENOMEM;
        }

        if (copy_from_user(file_path, pathname, MAX_PATH_LENGTH) != 0) {
            printk(KERN_ERR "Errore nella copia del percorso del file\n");
            kfree(file_path);
            if (path != NULL) kfree(path);
            return -EFAULT;
        }
        
        if (strcmp("/home/luca/Documenti/test", file_directory) == 0) {
            printk("%s: Tentativo di creare il file %s in una directory protetta.\n", MODNAME, file_directory);
        } else {
        	printk("%s: Tentativo di creare il file %s in una directory non protetta.\n", MODNAME, file_directory);
        }

       
    }*/

    return 0;
}

static struct kprobe kp = {
    .pre_handler = openat_pre_handler,
    .symbol_name = "do_sys_openat2",
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

MODULE_LICENSE("GPL");

