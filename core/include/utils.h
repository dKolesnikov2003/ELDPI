#ifndef UTILS_H
#define UTILS_H

extern char name_pattern[128];

long long now_ms(void);
int ensure_dir_exists(const char *dir);

#endif // UTILS_H