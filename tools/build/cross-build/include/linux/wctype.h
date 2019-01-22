#pragma once
#include_next <wctype.h>

#ifndef iswascii
#define iswascii(c) isascii(c)
#endif
