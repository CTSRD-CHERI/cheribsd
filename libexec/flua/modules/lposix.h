/*-
 *
 * This file is in the public domain.
 */
/* $FreeBSD$ */

#pragma once

#include <lua.h>

int luaopen_posix_sys_stat(lua_State *L);
int luaopen_posix_unistd(lua_State *L);
