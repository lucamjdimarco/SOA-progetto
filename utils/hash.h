int hash_password(const char *plaintext, unsigned char *output);
int compare_hash(char __user *password, unsigned char *hash_passwd);