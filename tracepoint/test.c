#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

static struct kprobe kp;

int my_kprobe_handler(struct kprobe *p, struct pt_regs *regs) {
    // La tua logica qui per intercettare la chiamata sys_enter_openat2
    pr_info("Chiamata a sys_enter_openat2 intercettata!\n");
    return 0;
}

static int __init kprobe_init(void) {
    kp.pre_handler = my_kprobe_handler;
    kp.symbol_name = "sys_enter_openat2";

    if (register_kprobe(&kp) < 0) {
        pr_err("Errore durante la registrazione della kprobe\n");
        return -1;
    }
    pr_info("Kprobe registrata con successo per sys_enter_openat2!\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    pr_info("Kprobe rimossa\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
