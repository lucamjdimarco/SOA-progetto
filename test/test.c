#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>  // for spin_lock, spin_unlock
#include <linux/errno.h>
#include <linux/file.h>

#define PATH 512

//krpobe struct
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

int get_absolute_path(const char __user *filename) {
    struct path path;
    int dfd = AT_FDCWD;
    char *ret_ptr = NULL;
    int error = -EINVAL;
    int flag = 0;
    unsigned int lookup_flags = 0;
    char *tpath = kmalloc(1024, GFP_KERNEL);

    if (!(flag & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

    error = user_path_at(dfd, filename, lookup_flags, &path);
    if (error) {
    	//printk("err\n");
        goto out;
     }

    ret_ptr = d_path(&path, tpath, 1024);
    printk("%s\n", ret_ptr);
    kfree(tpath);
    return 0;

out:
    kfree(tpath);
    return error;
}




/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file


    int fd = (int)(regs->di);
    struct open_how *how = (struct open_how *)regs->dx;
    
    //char *path = kmalloc(PATH, GFP_KERNEL);

    // NON GESTISCO IL VALORE DI RITORNO DELLA STRINGA DEL PATH COMPLETO
    //LA STAMPO SOLTANTO

    int ret = 0;

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }
        
        if(strncmp_custom(path, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path, "/", 1) != 0) {
            ret = get_absolute_path(filename);
            if (ret != 0) {
                printk(KERN_INFO "Failed to get full path\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path: %s\n", path);
            }
        }
        

        // Controlla se il file è aperto in scrittura o lettura/scrittura
        if (how->flags & O_WRONLY) {
            printk(KERN_INFO "File opened in write-only mode.\n");
        } else if (how->flags & O_RDWR) {
            printk(KERN_INFO "File opened in read-write mode.\n");
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
