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

#define PATH 256

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

/*int get_full_path(unsigned int fd, char *full_path){
    char *tmp;
    //char *pathname;
    struct file *file;
    struct path *path;

    struct files_struct *files = current->files;

    spin_lock(&files->file_lock);
    file = files_lookup_fd_rcu(files, fd);
    if (!file) {
        spin_unlock(&files->file_lock);
        return -ENOENT;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);

    tmp = (char *)__get_free_page(GFP_KERNEL);

    if (!tmp) {
        path_put(path);
        return -ENOMEM;
    }

    full_path = d_path(path, tmp, PAGE_SIZE);
    path_put(path);

    if (IS_ERR(full_path)) {
        free_page((unsigned long)tmp);
        return PTR_ERR(full_path);
    }

    free_page((unsigned long)tmp);

    return 0;
}*/

int get_full_path(int dfd){
    char *tmp = (char*)__get_free_page(SLAB_TEMPORARY);

    struct file *file = fget(dfd);
    
    if (!file) {
    	free_page((unsigned long)tmp);
        return 1;
    }

    char *path = d_path(&file->f_path, tmp, PAGE_SIZE);
    if (IS_ERR(path)) {
    	
        //printk("error: %d\n", (int)path);
        free_page((unsigned long)tmp);
        return 1;
    }
    
    printk(KERN_INFO "Sono alla fine\n");

    printk(KERN_INFO "path: %s\n", path);
    printk(KERN_INFO "tmp: %s\n", tmp);
    free_page((unsigned long)tmp);
    return 0;
}



/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file

    int fd = (int)regs->di;
    //manca il fatto che non recupera il path assoluto sempre
    //non ancora gestisco i flag

    char *full_path = kmalloc(PATH, GFP_KERNEL);
    int ret = 0;

    
    
    

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }
        
        if(strncmp_custom(filename, "/run", 4) == 0) {
            return 0;
        }

        //se fd == AT_FDCWD allora il path è assoluto
        if(fd != AT_FDCWD){
        	//printk(KERN_INFO "path non abs: %s\n", path);
            //ret = get_full_path(fd, filename);
            get_full_path(fd);
        } /*else {
        	printk(KERN_INFO "File Path: %s\n", path);
        }*/
        


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
