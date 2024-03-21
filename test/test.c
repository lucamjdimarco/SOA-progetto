#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>

#define PATH 4096


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

int get_absolute_path(const char __user *filename, char *buffer, size_t buf_size) {
    struct path path;
    int error = -EINVAL;
    unsigned int lookup_flags = LOOKUP_FOLLOW; // Segue i link simbolici di default

    if (!filename || !buffer) return -EINVAL;

    // Risolve il percorso dell'utente in una struct path
    error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
    if (error) return error;

    // Converte la struct path in una stringa di percorso, verificando la dimensione del buffer
    char *ret_ptr = d_path(&path, buffer, buf_size);
    if (IS_ERR(ret_ptr)) {
        error = PTR_ERR(ret_ptr);
    } else {
        // Copia il percorso nel buffer fornito dal chiamante, se desiderato
        if (ret_ptr != buffer) {
            strncpy(buffer, ret_ptr, buf_size);
            buffer[buf_size - 1] = '\0'; // Assicura la terminazione della stringa
        }
        error = 0; // Successo
    }

    path_put(&path); // Rilascia la reference acquisita da user_path_at
    return error;
}


/* Funzione di gestione pre-intercettazione */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    //printk(KERN_INFO "Intercepted do_sys_openat2\n");
    char path[PATH];
    char absolute_path[PATH_MAX]; // Buffer per il percorso assoluto
    const char __user *filename = (const char __user *)regs->si; // Registri che contengono il puntatore al path del file

    //unsigned int dfd = (unsigned int)regs->di;
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
        if (get_absolute_path(filename, absolute_path, PATH_MAX) == 0) {
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
