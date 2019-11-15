#pragma once

/* Ensure that we use the FreeBSD version of the db functions */
#define dbopen __freebsd_dbopen
#include "../../../../../include/db.h"
