#if defined(__has_include_next) && __has_include_next(<sys/stdint.h>)
#include_next <sys/stdint.h>
#else
#include <stdint.h>
#endif


/* opensolaris weirdness: */
typedef long long longlong_t;
typedef unsigned long ulong_t;
typedef uint64_t u_int64_t;
