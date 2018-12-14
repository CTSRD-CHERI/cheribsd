/* Used to workaround system headers with struct members called __unused */
#ifdef __unused_undefd
#undef __unused_undefd
#define __unused __attribute__((unused))
#endif
