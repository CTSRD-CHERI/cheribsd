#pragma once
#include_next <stdlib.h>

int rpmatch(const char *response);

long long
strtonum(const char *numstr, long long minval, long long maxval,
         const char **errstrp);

void *
reallocarray(void *optr, size_t nmemb, size_t size);
