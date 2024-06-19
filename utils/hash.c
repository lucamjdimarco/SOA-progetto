#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <linux/module.h>

#define SHA256_LENGTH 32

MODULE_AUTHOR("Luca Di Marco");
MODULE_DESCRIPTION("Aux function for the reference monitor");
MODULE_LICENSE("GPL");

int hash_password(const char *plaintext, unsigned char *output) {
    struct crypto_shash *sha256;
    struct shash_desc *shash;
    int size, ret;

     if (!plaintext || !output) {
        printk(KERN_ERR "Invalid input to hash_password\n");
        return -EINVAL;
    }

    sha256 = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256)) {
        return PTR_ERR(sha256);
    }

    size = sizeof(struct shash_desc) + crypto_shash_descsize(sha256);
    shash = kmalloc(size, GFP_KERNEL);
    if (!shash) {
        printk(KERN_ERR "Failed to allocate shash descriptor\n");
        crypto_free_shash(sha256);
        return -ENOMEM;
    }

    shash->tfm = sha256;
    //shash->flags = 0x0;

    ret = crypto_shash_digest(shash, plaintext, strlen(plaintext), output);
    if (ret) {
        printk(KERN_ERR "crypto_shash_digest failed: %d\n", ret);
    }
    
    kfree(shash);
    crypto_free_shash(sha256);

    return ret;
}

int compare_hash(char *password, unsigned char *hash_passwd) {
    //char *password = "password123";
    //int value;
    unsigned char hash[SHA256_LENGTH];

    if (hash_password(password, hash) == 0) {
        // Hash calcolato con successo
        printk(KERN_INFO "Password hashed\n");
        //prima usavo strncmp
        if(memcmp(hash, hash_passwd, SHA256_LENGTH) == 0) {
            // Password corretta
            printk(KERN_INFO "Password correct\n");
        } else {
            // Password errata
            printk(KERN_INFO "Password incorrect\n");
            return -1;
        }

    } else {
        // Errore nel calcolo dell'hash
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    return 0;
}

