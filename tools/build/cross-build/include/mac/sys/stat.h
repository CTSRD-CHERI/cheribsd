#include_next <sys/stat.h>

#ifndef UTIME_NOW
int utimensat(int fd, const char *file, const struct timespec *ts, int flag)
#endif

#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#define st_btim st_birthtimespec
#define st_birthtim st_birthtimespec
#define st_atimensec st_atimespec.tv_nsec
#define st_mtimensec st_mtimespec.tv_nsec
#define st_ctimensec st_ctimespec.tv_nsec
#define st_birthtimensec st_birthtimespec.tv_nsec
