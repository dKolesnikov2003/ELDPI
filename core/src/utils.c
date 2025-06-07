#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

char name_pattern[128];

long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int ensure_dir_exists(const char *dir)
{
    if (!dir || !*dir) return -1;
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s", dir);

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return (mkdir(tmp, 0755) && errno != EEXIST) ? -1 : 0;
}