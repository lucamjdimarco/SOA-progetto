#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
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
#include <linux/string.h>
#include <linux/syscalls.h>
#include "utils/hash.h"
#include "utils/func_aux.h"

#define PATH 512
#define MAX_LEN 50
#define PASS_LEN 20
#define SHA256_LENGTH 32

struct r_monitor {
    char *path[MAX_LEN]; //array di puntatori ai path da proteggere
    int last_index; //indice dell'ultimo path inserito
    int mode; //0 = OFF; 1 = ON; 2 = REC_OFF; 3 = REC_ON;
    char password[PASS_LEN];
    int changed_pswd; //se 0 è da controllare con "default" se 1 è da controllare con "new_password"
    spinlock_t lock;
};

struct r_monitor monitor;


unsigned long syscall_table_address = 0x0;

//module_param(syscall_table_address, ulong, 0660);

//viene indicato il 7 poiché avrò bisogno di 7 sys call --> devo trovare 7 indici liberi
int free_index[7];

static struct kprobe kp_openat2;
static struct kprobe kp_filp_open;
static struct kprobe kp_rmdir;
static struct kprobe kp_mkdir_at;
static struct kprobe kp_unlinkat;

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
};

static int handler_openat2(struct kprobe *p, struct pt_regs *regs) {
    char path[PATH];
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file
    //int fd = (int)(regs->di);
    struct open_how *how = (struct open_how *)regs->dx;
    char *ret_ptr = NULL;

    if (filename) {
        if (strncpy_from_user(path, filename, PATH) < 0) {
            //printk(KERN_INFO "Failed to copy filename from user space\n");
            return 0;
        }
        
        if(strncmp_custom(path, "/run", 4) == 0) {
            return 0;
        }

        if ((how->flags & O_WRONLY) || (how->flags & O_CREAT) || (how->flags & O_TRUNC) || (how->flags & O_APPEND) || (how->flags & O_RDWR)) {
            if(strncmp_custom(path, "/", 1) != 0) {
                ret_ptr = get_absolute_path(filename);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path openat2\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path openat2: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path openat2: %s\n", path);
            }
        }
        
        /*if ((how->flags & O_WRONLY) || (how->flags & O_CREAT) || (how->flags & O_TRUNC) || (how->flags & O_APPEND) || (how->flags & O_RDWR)) {
            printk(KERN_INFO "File opened in write mode.\n");
        }*/
        
    } else {
        printk(KERN_INFO "No filename provided\n");
    }




    return 0;
}

static int handler_filp_open(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int)regs->di;
    //struct filename *filename = (struct filename *)regs->si;
    struct open_flags *op = (struct open_flags *)(regs->dx);
    //int flag = op->open_flag;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    if ((op->open_flag & O_WRONLY) || (op->open_flag & O_CREAT) || (op->open_flag & O_TRUNC) || (op->open_flag & O_APPEND) || (op->open_flag & O_RDWR)) {
            //printk(KERN_INFO "File opened in write mode.\n");
        if(path_user == NULL){
            //uso path kernel 
            if(strncmp_custom(path_kernel, "/run", 4) == 0) {
                return 0;
            }

            if(strncmp_custom(path_kernel, "/", 1) != 0) {
                ret_ptr = get_absolute_path(path_kernel);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path do_filp_open\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path do_filp_open: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path do_filp_open: %s\n", path_kernel);
            }

        } else {
            //uso path user
            if(strncmp_custom(path_user, "/run", 4) == 0) {
                return 0;
            }

            if(strncmp_custom(path_user, "/", 1) != 0) {
                ret_ptr = get_absolute_path(path_user);
                if (ret_ptr == NULL) {
                    printk(KERN_INFO "Failed to get full path do_filp_open\n");
                    return 0;
                } else {
                    printk(KERN_INFO "Full path do_filp_open: %s\n", ret_ptr);
                }
            } else {
                printk(KERN_INFO "Full path do_filp_open: %s\n", path_user);
            }
        }
    } else {
        return 0;
    }
    return 0;
}

static int handler_rmdir(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path rmdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path rmdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path rmdir: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path rmdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path rmdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path rmdir: %s\n", path_user);
        }
    }
    
    return 0;
}

static int handler_mkdirat(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    
    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path mkdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path mkdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path mkdir: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path mkdir\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path mkdir: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path mkdir: %s\n", path_user);
        }
    }
    
    return 0;
}

static int handler_unlinkat(struct kprobe *p, struct pt_regs *regs) {
    
    //int fd = (int)regs->di;

    const __user char *path_user = ((struct filename *)(regs->si))->uptr;
	const char *path_kernel = ((struct filename *)(regs->si))->name;

    char *ret_ptr = NULL;

    
    if(path_user == NULL){
        //uso path kernel 
        if(strncmp_custom(path_kernel, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_kernel, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_kernel);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path unlinkat\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path unlinkat: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path unlinkat: %s\n", path_kernel);
        }

    } else {
        //uso path user
        if(strncmp_custom(path_user, "/run", 4) == 0) {
            return 0;
        }

        if(strncmp_custom(path_user, "/", 1) != 0) {
            ret_ptr = get_absolute_path(path_user);
            if (ret_ptr == NULL) {
                printk(KERN_INFO "Failed to get full path unlinkat\n");
                return 0;
            } else {
                printk(KERN_INFO "Full path unlinkat: %s\n", ret_ptr);
            }
        } else {
            printk(KERN_INFO "Full path unlinkat: %s\n", path_user);
        }
    }
    
    return 0;
}


/*__SYSCALL_DEFINEx(1, _monitor_OFF, char __user *, passwd){
    printk(KERN_INFO "Stopping monitor ... \n");

    int ret;
    size_t len = strlen_user(passwd);
    char *str = kmalloc(len + 1, GFP_KERNEL);
    if (str == NULL) {
        return -ENOMEM;
    }
    
    ret = strncpy_from_user(str, passwd, len);
    if (ret != 0) {
        kfree(str);
        return -EFAULT;
    }


    spin_lock(&monitor.lock);

    //IN TUTTE LE SYS CALL BISOGNA INSERIRE LA PASSWORD E CONTROLLARLA RISPETTO QUELLA SALVATA HASHATA

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, len) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }
    
    monitor.mode = 0;
    disable_kprobe(&kp_openat2);
    disable_kprobe(&kp_filp_open);
    disable_kprobe(&kp_rmdir);
    disable_kprobe(&kp_mkdir_at);
    disable_kprobe(&kp_unlinkat);

    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Monitor OFF\n");
    return 0;
}

__SYSCALL_DEFINEx(1, _monitor_ON, char __user *, passwd){
    printk(KERN_INFO "Starting monitor ... \n");

    int ret;
    size_t len = strlen_user(passwd);
    char *str = kmalloc(len + 1, GFP_KERNEL);
    if (str == NULL) {
        return -ENOMEM;
    }
    
    ret = strncpy_from_user(str, passwd, len);
    if (ret != 0) {
        kfree(str);
        return -EFAULT;
    }

    spin_lock(&monitor.lock);

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, len) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }

    monitor.mode = 1;
    enable_kprobe(&kp_openat2);
    enable_kprobe(&kp_filp_open);
    enable_kprobe(&kp_rmdir);
    enable_kprobe(&kp_mkdir_at);
    enable_kprobe(&kp_unlinkat);

    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Monitor ON\n");
    return 0;
}


__SYSCALL_DEFINEx(1, _monitor_REC_OFF, char __user *, passwd){
    printk(KERN_INFO "Starting monitor reconfiguration REC_OFF ... \n");

    int ret;
    size_t len = strlen_user(passwd);
    char *str = kmalloc(len + 1, GFP_KERNEL);
    if (str == NULL) {
        return -ENOMEM;
    }
    
    ret = strncpy_from_user(str, passwd, len);
    if (ret != 0) {
        kfree(str);
        return -EFAULT;
    }

    spin_lock(&monitor.lock);

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, len) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(passwd, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }

    monitor.mode = 2;
    disable_kprobe(&kp_openat2);
    disable_kprobe(&kp_filp_open);
    disable_kprobe(&kp_rmdir);
    disable_kprobe(&kp_mkdir_at);
    disable_kprobe(&kp_unlinkat);

    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Monitor REC_OFF\n");
    return 0;
}

__SYSCALL_DEFINEx(1, _monitor_REC_ON, char __user *, passwd){
    printk(KERN_INFO "Starting monitor reconfiguration REC_ON... \n");

    int ret;
    size_t len = strlen_user(passwd);
    char *str = kmalloc(len + 1, GFP_KERNEL);
    if (str == NULL) {
        return -ENOMEM;
    }
    
    ret = strncpy_from_user(str, passwd, len);
    if (ret != 0) {
        kfree(str);
        return -EFAULT;
    }

    spin_lock(&monitor.lock);

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, len) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }

    monitor.mode = 3;
    enable_kprobe(&kp_openat2);
    enable_kprobe(&kp_filp_open);
    enable_kprobe(&kp_rmdir);
    enable_kprobe(&kp_mkdir_at);
    enable_kprobe(&kp_unlinkat);

    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Monitor REC_ON\n");
    return 0;
}

__SYSCALL_DEFINEx(2, _insert_path, char __user *, path, char __user *, passwd){
    printk(KERN_INFO "Inserting path ... \n");

    int ret;
    size_t len_path = strlen_user(path);
    char *str_path = kmalloc(len_path + 1, GFP_KERNEL);
    if (str_path == NULL) {
        return -ENOMEM;
    }
    ret = strncpy_from_user(str_path, path, len_path);
    if (ret != 0) {
        kfree(str_path);
        return -EFAULT;
    }

    size_t len_pas = strlen_user(passwd);
    char *str_pass = kmalloc(len_pas + 1, GFP_KERNEL);
    if (str_pass == NULL) {
        return -ENOMEM;
    }
    ret = strncpy_from_user(str_pass, passwd, len_pas);
    if (ret != 0) {
        kfree(str_pass);
        return -EFAULT;
    }

    spin_lock(&monitor.lock);

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str_pass, len_pas) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str_pass, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }

    if(monitor.mode == 0 || monitor.mode == 1){
        printk(KERN_INFO "Monitor OFF or ON - not in REC mode\n");
        spin_unlock(&monitor.lock);
        return -1;
    }

    //forse bisogna diminuire path
    //DEVO ANCHE VERIFICARE CHE NON VENGA INSERITO PATH DEL SINGLE-FS
    if(monitor.last_index < MAX_LEN){
        for(int i = 0; i < monitor.last_index; i++){
            if(strncmp_custom(monitor.path[i], str_path, len_path) == 0){
                printk(KERN_INFO "Path already inserted\n");
                spin_unlock(&monitor.lock);
                return -1;
            }
        }
        if(strncpy_from_user(monitor.path[monitor.last_index], path, len_path) < 0){
            printk(KERN_INFO "Failed to copy path from user space\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
        monitor.last_index++;
    } else {
        printk(KERN_INFO "Max number of paths reached\n");
        spin_unlock(&monitor.lock);
        return -1;
    }

    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Path inserted\n");
    return 0;
}

__SYSCALL_DEFINEx(2, _remove_path, char __user *, path, char __user *, passwd){

    size_t len = strlen_user(passwd);
    char *str = kmalloc(len + 1, GFP_KERNEL);
    size_t len_path = strlen_user(path);
    char *str_path = kmalloc(len_path + 1, GFP_KERNEL);
    int value;

    if (str == NULL) {
        return -ENOMEM;
    }

    if (str_path == NULL) {
        return -ENOMEM;
    }

    value = strncpy_from_user(str, passwd, len);

    if (value != 0) {
        kfree(str);
        return -EFAULT;
    }

    value = strncpy_from_user(str_path, path, len_path);
    
    if (value != 0) {
        kfree(str_path);
        return -EFAULT;
    }

    printk(KERN_INFO "Removing path ... \n");
    spin_lock(&monitor.lock);
    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, PASS_LEN) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }

    if(monitor.mode == 0 || monitor.mode == 1){
        printk(KERN_INFO "Monitor OFF or ON - not in REC mode\n");
        spin_unlock(&monitor.lock);
        return -1;
    }

    for(int i = 0; i < monitor.last_index; i++){
        if(strncmp_custom(monitor.path[i], str_path, PATH) == 0){
            for(int j = i; j < monitor.last_index - 1; j++){
                monitor.path[j] = monitor.path[j+1];
            }
            monitor.last_index--;
            spin_unlock(&monitor.lock);
            printk(KERN_INFO "Path removed\n");
            return 0;
        }
    }

    printk(KERN_INFO "Path not found\n");
    spin_unlock(&monitor.lock);
    return -1;
}

__SYSCALL_DEFINEx(2, _set_password, char __user *, passwd, char __user *, new_passwd){
    printk(KERN_INFO "Setting password ... \n");

    int ret;
    size_t len_pas = strlen_user(passwd);
    size_t len_new_pas = strlen_user(new_passwd);
    char *str = kmalloc(len_pas + 1, GFP_KERNEL);
    if (str == NULL) {
        return -ENOMEM;
    }
    
    ret = strncpy_from_user(str, passwd, len_pas);
    if (ret != 0) {
        kfree(str);
        return -EFAULT;
    }

    spin_lock(&monitor.lock);

    if(monitor.changed_pswd == 0) {
        if(strncmp_custom(monitor.password, str, len_pas) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR default passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    } else {
        if(compare_hash(str, monitor.password) != 0 || getuid() != 0){
            printk(KERN_INFO "ERROR new passwd\n");
            spin_unlock(&monitor.lock);
            return -1;
        }
    }


    unsigned char hash_passwd[SHA256_LENGTH];
    char *new_pas = kmalloc(len_new_pas + 1, GFP_KERNEL);
    if (new_pas == NULL) {
        return -ENOMEM;
    }
    ret = strncpy_from_user(new_pas, new_passwd, len_new_pas);
    if (ret != 0) {
        kfree(new_pas);
        return -EFAULT;
    }
    if(hash_password(new_pas, hash_passwd) != 0){
        printk(KERN_INFO "Failed to hash password\n");
        spin_unlock(&monitor.lock);
        return -1;
    }

    // posso usare la strcnpy in questo modo???????

    if(strncpy(monitor.password, new_pas, len_new_pas) == NULL){
        printk(KERN_INFO "Failed to copy password\n");
        spin_unlock(&monitor.lock);
        return -1;
    }


    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Password set\n");
    return 0;
} */

static int __init monitor_init(void) {

    // Modifica della system call table - necessito di 7 entry 

    monitor.changed_pswd = 0;

    kp_openat2.pre_handler = handler_openat2;
    kp_openat2.symbol_name = "do_sys_openat2"; // Nome della funzione da intercettare

    kp_filp_open.pre_handler = handler_filp_open;
    kp_filp_open.symbol_name = "do_filp_open";

    kp_rmdir.pre_handler = handler_rmdir;
    kp_rmdir.symbol_name = "do_rmdir";

    kp_mkdir_at.pre_handler = handler_mkdirat;
    kp_mkdir_at.symbol_name = "do_mkdirat";

    kp_unlinkat.pre_handler = handler_unlinkat;
    kp_unlinkat.symbol_name = "do_unlinkat";


    if (register_kprobe(&kp_openat2) < 0) {
        printk(KERN_INFO "Failed to register kprobe openat2\n");
        return -1;
    }
    if (register_kprobe(&kp_filp_open) < 0) {
        printk(KERN_INFO "Failed to register kprobe filp_open\n");
        return -1;
    }
    if (register_kprobe(&kp_rmdir) < 0) {
        printk(KERN_INFO "Failed to register kprobe rmdir\n");
        return -1;
    }
    if (register_kprobe(&kp_mkdir_at) < 0) {
        printk(KERN_INFO "Failed to register kprobe mkdirat\n");
        return -1;
    }
    if(register_kprobe(&kp_unlinkat) < 0) {
        printk(KERN_INFO "Failed to register kprobe unlinkat\n");
        return -1;
    }
    printk(KERN_INFO "Kprobe openat2 registered successfully\n");
    printk(KERN_INFO "Kprobe filp_open registered successfully\n");
    printk(KERN_INFO "Kprobe rmdir registered successfully\n");
    printk(KERN_INFO "Kprobe mkdirat registered successfully\n");
    printk(KERN_INFO "Kprobe unlinkat registered successfully\n");
    return 0;
}

static void __exit monitor_exit(void) {
    unregister_kprobe(&kp_openat2);
    unregister_kprobe(&kp_filp_open);
    unregister_kprobe(&kp_rmdir);
    unregister_kprobe(&kp_mkdir_at);
    unregister_kprobe(&kp_unlinkat);
    printk(KERN_INFO "Kprobe openat2 unregistered\n");
    printk(KERN_INFO "Kprobe filp_open unregistered\n");
    printk(KERN_INFO "Kprobe rmdir unregistered\n");
    printk(KERN_INFO "Kprobe mkdirat unregistered\n");
    printk(KERN_INFO "Kprobe unlinkat unregistered\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Reference Monitor");