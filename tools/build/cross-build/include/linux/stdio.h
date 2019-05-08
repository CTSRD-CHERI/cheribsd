// Glibc can include this multiple times
#include_next <stdio.h>
__BEGIN_DECLS
char	*fgetln(FILE *, size_t *);
#if defined(_WCHAR_H)
wchar_t	*fgetwln(FILE * __restrict, size_t * __restrict);
#endif
__END_DECLS
