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
#include <linux/version.h>
#include <linux/device.h>
#include "utils/hash.h"
#include "utils/func_aux.h"

#define PATH 512
#define MAX_LEN 50
#define PASS_LEN 32
#define SHA256_LENGTH 32
#define TABLE_ENTRIES 7

#define DEVICE_NAME "ref_monitor"

static int Major;
static struct class* device_class = NULL;
static struct device* device = NULL;

struct r_monitor {
    char *path[MAX_LEN]; //array di puntatori ai path da proteggere
    int last_index; //indice dell'ultimo path inserito
    int mode; //0 = OFF; 1 = ON; 2 = REC_OFF; 3 = REC_ON;
    char password[PASS_LEN];
    int changed_pswd; //se 0 è da controllare con "default" se 1 è da controllare con "new_password"
    spinlock_t lock;
};

struct r_monitor monitor = {
    .password = "default",
    .changed_pswd = 0
};

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

static ssize_t ref_write(struct file *, const char *, size_t, loff_t *);
static int ref_open(struct inode *, struct file *);
// Dichiarazione delle funzioni di gestione
int setMonitorON(char *pass);
int setMonitorOFF(char *pass);
int setMonitorREC_ON(char *pass);
int setMonitorREC_OFF(char *pass);
int changePassword(char *new_password);
int comparePassw(char *pass);

static inline bool is_root_uid(void) {
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
        #include "linux/uidgid.h"
            // current_uid() returns struct in newer kernels
            printk(KERN_INFO "Check if root\n");
            printk(KERN_INFO "UID: %d\n", uid_eq(current_uid(), GLOBAL_ROOT_UID));
            return uid_eq(current_uid(), GLOBAL_ROOT_UID);
        #else
            printk(KERN_INFO "Check else root\n");
            return 0 == current_uid();
    #endif
}


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

int findNullTerminator(const char *str, size_t maxlen) {
    size_t i = 0;
    while (i < maxlen && str[i] != '\0') {
        i++;
    }

    if (i < maxlen && str[i] == '\0') {
        return i;  // Restituisce la posizione del terminatore nullo
    } else {
        return -1; // Se non trova il terminatore nullo entro maxlen
    }
}

int comparePassw(char *pass) {
    int ret;
    char hash[PASS_LEN + 1];
    ret = hash_password(pass, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    if(memcmp(hash, monitor.password, SHA256_LENGTH) == 0) {
        printk(KERN_INFO "Password correct\n");
        return 0;
    } else {
        printk(KERN_INFO "Password incorrect\n");
        return -1;
    }

}

int setMonitorON(char *pass) {
    int ret;
    char hash[PASS_LEN + 1];

    if(is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -1;
    }

    ret = hash_password(pass, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    if(comparePassw(hash) != 0) {
        printk(KERN_ERR "Error: password incorrect\n");
        return -1;
    }

    switch(monitor.mode){
        case 0:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            enable_kprobe(&kp_openat2);
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        case 1:
            printk(KERN_INFO "Monitor is already ON\n");
            break;
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            enable_kprobe(&kp_openat2);
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 1;
            spin_unlock(&monitor.lock);

            printk(KERN_INFO "Monitor is now ON\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
            return -1;
    }
    spin_lock(&monitor.lock);
    monitor.mode = 1;
    spin_unlock(&monitor.lock);
    printk(KERN_INFO "Monitor is now ON\n");
    return 0;
}

int setMonitorOFF(char *pass) {
    int ret;
    char hash[PASS_LEN + 1];

    if(is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -1;
    }
    
    ret = hash_password(pass, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    if(comparePassw(hash) != 0) {
        printk(KERN_ERR "Error: password incorrect\n");
        return -1;
    }

    switch(monitor.mode){
        case 0:
            printk(KERN_INFO "Monitor is already OFF\n");
            break;
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            disable_kprobe(&kp_openat2);
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 0;
            spin_unlock(&monitor.lock);

            disable_kprobe(&kp_openat2);
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now OFF\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
            return -1;
    }
    return 0;
}

int setMonitorREC_ON(char *pass) {
    int ret;
    char hash[PASS_LEN + 1];

    if(is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -1;
    }

    ret = hash_password(pass, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    int pos1 = findNullTerminator(pass, sizeof(pass));
    if (pos1 != -1) {
        printk(KERN_INFO, "La stringa1 ha il terminatore nullo alla posizione %d.\n", pos1);
    } else {
        printf(KERN_INFO, "La stringa1 non ha il terminatore nullo entro %zu caratteri.\n", sizeof(pass));
    }

    int pos2 = findNullTerminator(hash, sizeof(hash));
    if (pos2 != -1) {
        printf(KERN_INFO, "La stringa2 ha il terminatore nullo alla posizione %d.\n", pos2);
    } else {
        printf(KERN_INFO, "La stringa2 non ha il terminatore nullo entro %zu caratteri.\n", sizeof(pass));
    }

    printk(KERN_INFO "Passwd: %s\n", monitor.password);

    printk(KERN_INFO "Passwd: %s\n", hash);

    if(comparePassw(hash) != 0) {
        printk(KERN_ERR "Error: password incorrect\n");
        return -1;
    }

    switch(monitor.mode){
        case 0:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);
            
            enable_kprobe(&kp_openat2);
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);
            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        case 2:
            spin_lock(&monitor.lock);
            monitor.mode = 3;
            spin_unlock(&monitor.lock);

            enable_kprobe(&kp_openat2);
            enable_kprobe(&kp_filp_open);
            enable_kprobe(&kp_rmdir);
            enable_kprobe(&kp_mkdir_at);
            enable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_ON\n");
            break;
        case 3:
            printk(KERN_INFO "Monitor is already REC_ON\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
            return -1;
    }
    return 0;
}

int setMonitorREC_OFF(char *pass) {
    int ret;
    char hash[PASS_LEN + 1];

    if(is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -1;
    }

    ret = hash_password(pass, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    if(comparePassw(hash) != 0) {
        printk(KERN_ERR "Error: password incorrect\n");
        return -1;
    }

    switch(monitor.mode){
        case 0:
            printk(KERN_INFO "Monitor is already REC_OFF\n");
            break;
        case 1:
            spin_lock(&monitor.lock);
            monitor.mode = 2;
            spin_unlock(&monitor.lock);

            disable_kprobe(&kp_openat2);
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_OFF\n");
            break;
        case 2:
            printk(KERN_INFO "Monitor is already REC_OFF\n");
            break;
        case 3:
            spin_lock(&monitor.lock);
            monitor.mode = 2;
            spin_unlock(&monitor.lock);

            disable_kprobe(&kp_openat2);
            disable_kprobe(&kp_filp_open);
            disable_kprobe(&kp_rmdir);
            disable_kprobe(&kp_mkdir_at);
            disable_kprobe(&kp_unlinkat);

            printk(KERN_INFO "Monitor is now REC_OFF\n");
            break;
        default:
            printk(KERN_ERR "Error: invalid mode\n");
            return -1;
    }
    return 0;
}

int changePassword(char *new_password) {
    int ret;
    char hash[PASS_LEN + 1];

    if(is_root_uid() != 1) {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -1;
    }

    printk(KERN_INFO "Changing password - setting the monitor REC_ON or REC_OFF\n");
    
    if(monitor.mode == 0) {
        spin_lock(&monitor.lock);  
        monitor.mode = 2;
        spin_unlock(&monitor.lock);
    } else if(monitor.mode == 1) {
        spin_lock(&monitor.lock);  
        monitor.mode = 3;
        spin_unlock(&monitor.lock);
    }

    /*if((monitor.mode != 2 || monitor.mode != 3) || is_root_uid() != 1){
        printk(KERN_ERR "Error: Monitor is not in REC mode or not ROOT user - try again\n");
        return -1;
    }*/


    ret = hash_password(new_password, hash);
    if(ret != 0) {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    printk(KERN_INFO "Password changed\n");

    spin_lock(&monitor.lock);
    strncpy(monitor.password, hash, PASS_LEN);
    monitor.changed_pswd = 1;
    spin_unlock(&monitor.lock);

    printk(KERN_INFO "Password changed - reset the monitor\n");
    if(monitor.mode == 2) {
        spin_lock(&monitor.lock);  
        monitor.mode = 0;
        spin_unlock(&monitor.lock);
    } else if(monitor.mode == 3) {
        spin_lock(&monitor.lock);  
        monitor.mode = 1;
        spin_unlock(&monitor.lock);
    }


    return 0;
}



static int ref_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Open\n");
    return 0;
}

static ssize_t ref_write(struct file *f, const char *buff, size_t len, loff_t *off) {

    char *buffer = kmalloc(1024, GFP_KERNEL);
    int ret;

    if (!buffer) {
	    printk(KERN_ERR "Error on allocating memory\n");
        kfree(buffer);
	    return -ENOMEM;
	}

    if(len > 1024) {
        printk(KERN_ERR "Error: too data\n");
        kfree(buffer);
        return -EINVAL;
    }

    ret = copy_from_user(buffer, buff, len);

    if (ret) {
        printk(KERN_ERR "Error on copy_from_user\n");
        kfree(buffer);
        return -EFAULT;
    }

    buffer[len] = '\0'; // Assicurati che il buffer sia null-terminated

    // Estrai i due argomenti
    char *command = strsep(&buffer, ":");
    char *parameter = buffer;

    if (command && parameter) {
        printk(KERN_INFO "Received command: %s with parameter: %s\n", command, parameter);

        if (strncmp(command, "ON", 2) == 0) {
            printk(KERN_INFO "Monitor is setting ON\n");
            setMonitorON(parameter);
        } else if (strncmp(command, "OFF", 3) == 0) {
            setMonitorOFF(parameter);
        } else if (strncmp(command, "REC_ON", 6) == 0) {
            setMonitorREC_ON(parameter);
        } else if (strncmp(command, "REC_OFF", 7) == 0) {
            setMonitorREC_OFF(parameter);
        } else if (strncmp(command, "CHGPASS", 7) == 0) {
            changePassword(parameter);
        } else if (strncmp(command, "CMP", 3) == 0){
            comparePassw(parameter);        
        } else {
            printk(KERN_ERR "Error: invalid command\n");
            kfree(buffer);
            return -EINVAL;
        }
    } else {
        printk(KERN_ERR "Error: invalid input format\n");
        kfree(buffer);
        return -EINVAL;
    }
    
    kfree(buffer);


    return len;

}



static struct file_operations fops = {
  .owner = THIS_MODULE,	
  .write = ref_write,
  .open = ref_open,
};

static int __init monitor_init(void) {

    printk(KERN_INFO "Monitor module loaded\n");

    Major = register_chrdev(0, DEVICE_NAME, &fops);
    if (Major < 0) {
        printk(KERN_ALERT "Registering char device failed with %d\n", Major);
        return Major;
    }

    // Creazione della classe del dispositivo
    device_class = class_create(DEVICE_NAME);
    if (IS_ERR(device_class)) {
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Class creation failed\n");
        return PTR_ERR(device_class);
    }

    // Creazione del dispositivo
    device = device_create(device_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device)) {
        class_destroy(device_class);
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Device creation failed\n");
        return PTR_ERR(device);
    }


    printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);



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

    printk(KERN_INFO "Monitor module unloaded\n");

    // Rimozione del dispositivo
    device_destroy(device_class, MKDEV(Major, 0));
    class_unregister(device_class);
    class_destroy(device_class);
    unregister_chrdev(Major, DEVICE_NAME);

    //unregister_chrdev(Major, DEVICE_NAME);

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