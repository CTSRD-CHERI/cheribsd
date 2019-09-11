// Glibc can include this multiple times
#include_next <stdio.h>
__BEGIN_DECLS
char	*fgetln(FILE *, __SIZE_TYPE__ *);
#if defined(_WCHAR_H)
__WCHAR_TYPE__	*fgetwln(FILE * __restrict, __SIZE_TYPE__ * __restrict);
#endif
__END_DECLS
