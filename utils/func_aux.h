#ifdef FUNC_AUX_H
#define FUNC_AUX_H

int strncmp_custom(const char *s1, const char *s2, size_t n);
char *get_absolute_path(const char __user *filename);

#endif