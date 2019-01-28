#pragma once

/* Work around #include cycle error between unistd and getopt with libbsd */
#include <getopt.h>
#include_next <archive.h>
