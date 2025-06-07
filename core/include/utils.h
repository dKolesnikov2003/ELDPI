#ifndef UTILS_H
#define UTILS_H

extern char name_pattern[128];

#define BATCH_MAX 512
#define BATCH_MAX_MS 1000 

long long now_ms(void);
int ensure_dir_exists(const char *dir);

#endif // UTILS_H