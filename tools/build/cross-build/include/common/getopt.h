#pragma once

#define getopt __freebsd_getopt
#define getopt_long __freebsd_getopt_long
#define getopt_long_only __freebsd_getopt_long_only
#define opterr __freebsd_opterr
#define optind __freebsd_optind
#define optopt __freebsd_optopt
#define optreset __freebsd_optreset
#define optarg __freebsd_optarg

/* Since we are building the FreeBSD getopt.c also use the matching header */
#include "../../../../../include/getopt.h"

#undef getopt
#define getopt(argc, argv, optstr) __freebsd_getopt(argc, argv, optstr)
