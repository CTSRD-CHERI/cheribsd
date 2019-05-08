#pragma once

#include_next <grp.h>

#define	group_from_gid	__nbcompat_group_from_gid

int
pwcache_groupdb(
        int		(*a_setgroupent)(int),
        void		(*a_endgrent)(void),
        struct group *	(*a_getgrnam)(const char *),
        struct group *	(*a_getgrgid)(gid_t));

int
gid_from_group(const char *name, gid_t *gid);

int
gid_from_group(const char *name, gid_t *gid);

const char *
group_from_gid(gid_t gid, int noname);

#ifdef __linux__
static inline int
setgroupent(int stayopen)
{
  setgrent();
  return 1;
}
#endif

