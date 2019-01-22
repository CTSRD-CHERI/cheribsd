#pragma once

#ifdef NEED_FREEBSD_STRUCT_PASSWD
/* When building pwd_mkdb we need to use the FreeBSD definition of struct passwd */
#define _GID_T_DECLARED
#define _TIME_T_DECLARED
#define _UID_T_DECLARED
#define _SIZE_T_DECLARED
#include "../../../../../include/pwd.h"
#else
#include_next <pwd.h>

#define	user_from_uid	__nbcompat_user_from_uid

int
pwcache_userdb(
        int		(*a_setpassent)(int),
        void		(*a_endpwent)(void),
        struct passwd *	(*a_getpwnam)(const char *),
        struct passwd *	(*a_getpwuid)(uid_t));

int
uid_from_user(const char *name, uid_t *uid);

int
uid_from_user(const char *name, uid_t *uid);
const char *
user_from_uid(uid_t uid, int noname);

#ifdef __linux__
static inline int
setpassent(int stayopen)
{
  setpwent();
  return 1;
}
#endif

#endif
