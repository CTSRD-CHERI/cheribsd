#pragma once
#include_next <vis.h>
// libbsd shippend with Ubuntu 16.04 is missing some prototypes:1
int strsvis(char *dst, const char *src, int flag, const char *extra);
