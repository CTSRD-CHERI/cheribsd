#pragma once
#include_next <stdlib.h>

__BEGIN_DECLS
/* Add the getcap functions */
char	*cgetcap(char *, const char *, int);
int	 cgetclose(void);
int	 cgetent(char **, char **, const char *);
int	 cgetfirst(char **, char **);
int	 cgetmatch(const char *, const char *);
int	 cgetnext(char **, char **);
int	 cgetnum(char *, const char *, long *);
int	 cgetset(const char *);
int	 cgetstr(char *, const char *, char **);
int	 cgetustr(char *, const char *, char **);


const char	*getprogname(void);
void		 setprogname(const char *progname);

void	*reallocarray(void *, size_t, size_t) __result_use_check
	    __alloc_size2(2, 3);
void	*reallocf(void *, size_t) __result_use_check __alloc_size(2);

__uint32_t	arc4random(void);
void	 arc4random_buf(void *, size_t);
__uint32_t	arc4random_uniform(__uint32_t);

long long
	strtonum(const char *, long long, long long, const char **);

int	 heapsort(void *, size_t, size_t, int (*)(const void *, const void *));
int	 mergesort(void *, size_t, size_t, int (*)(const void *, const void *));

__END_DECLS
