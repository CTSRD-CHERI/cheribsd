/*-
 * Copyright (c) 1998 Michael Smith
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The unified bootloader passes us a pointer to a preserved copy of
 * bootstrap/kernel environment variables.  We convert them to a
 * dynamic array of strings later when the VM subsystem is up.
 *
 * We make these available through the kenv(2) syscall for userland
 * and through kern_getenv()/freeenv() kern_setenv() kern_unsetenv() testenv() for
 * the kernel.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/libkern.h>
#include <sys/kenv.h>

#include <security/mac/mac_framework.h>

static MALLOC_DEFINE(M_KENV, "kenv", "kernel environment");

#define KENV_SIZE	512	/* Maximum number of environment strings */

/* pointer to the static environment */
char		*kern_envp;
static int	env_len;
static int	env_pos;
static char	*kernenv_next(char *);

/* dynamic environment variables */
char		**kenvp;
struct mtx	kenv_lock;

/*
 * No need to protect this with a mutex since SYSINITS are single threaded.
 */
int	dynamic_kenv = 0;

#define KENV_CHECK	if (!dynamic_kenv) \
			    panic("%s: called before SI_SUB_KMEM", __func__)

#ifndef _SYS_SYSPROTO_H_
struct kenv_args {
	int what;
	const char *name;
	char *value;
	int len;
};
#endif
int
sys_kenv(struct thread *td, struct kenv_args *uap)
{

	return (kern_kenv(td, uap->what,
	    (__cheri_cast const char * __CAPABILITY)uap->name,
	    (__cheri_cast char * __CAPABILITY)uap->value, uap->len));
}

int
kern_kenv(struct thread *td, int what, const char * __CAPABILITY namep,
    char * __CAPABILITY val, int vallen)
{
	char *name, *value, *buffer = NULL;
	size_t len, done, needed, buflen;
	int error, i;

	KASSERT(dynamic_kenv, ("kenv: dynamic_kenv = 0"));

	error = 0;
	if (what == KENV_DUMP) {
#ifdef MAC
		error = mac_kenv_check_dump(td->td_ucred);
		if (error)
			return (error);
#endif
		done = needed = 0;
		buflen = vallen;
		if (buflen > KENV_SIZE * (KENV_MNAMELEN + KENV_MVALLEN + 2))
			buflen = KENV_SIZE * (KENV_MNAMELEN +
			    KENV_MVALLEN + 2);
		if (vallen > 0 && val != NULL)
			buffer = malloc(buflen, M_TEMP, M_WAITOK|M_ZERO);
		mtx_lock(&kenv_lock);
		for (i = 0; kenvp[i] != NULL; i++) {
			len = strlen(kenvp[i]) + 1;
			needed += len;
			len = min(len, buflen - done);
			/*
			 * If called with a NULL or insufficiently large
			 * buffer, just keep computing the required size.
			 */
			if (val != NULL && buffer != NULL && len > 0) {
				bcopy(kenvp[i], buffer + done, len);
				done += len;
			}
		}
		mtx_unlock(&kenv_lock);
		if (buffer != NULL) {
			error = copyout_c((__cheri_cast char * __CAPABILITY)buffer,
			    val, done);
			free(buffer, M_TEMP);
		}
		td->td_retval[0] = ((done == needed) ? 0 : needed);
		return (error);
	}

	switch (what) {
	case KENV_SET:
		error = priv_check(td, PRIV_KENV_SET);
		if (error)
			return (error);
		break;

	case KENV_UNSET:
		error = priv_check(td, PRIV_KENV_UNSET);
		if (error)
			return (error);
		break;
	}

	name = malloc(KENV_MNAMELEN + 1, M_TEMP, M_WAITOK);

	error = copyinstr_c(namep, (__cheri_cast char * __CAPABILITY)name,
	    KENV_MNAMELEN + 1, NULL);
	if (error)
		goto done;

	switch (what) {
	case KENV_GET:
#ifdef MAC
		error = mac_kenv_check_get(td->td_ucred, name);
		if (error)
			goto done;
#endif
		value = kern_getenv(name);
		if (value == NULL) {
			error = ENOENT;
			goto done;
		}
		len = strlen(value) + 1;
		if (len > vallen)
			len = vallen;
		error = copyout_c((__cheri_cast char * __CAPABILITY)value, val,
		    len);
		freeenv(value);
		if (error)
			goto done;
		td->td_retval[0] = len;
		break;
	case KENV_SET:
		len = vallen;
		if (len < 1) {
			error = EINVAL;
			goto done;
		}
		if (len > KENV_MVALLEN + 1)
			len = KENV_MVALLEN + 1;
		value = malloc(len, M_TEMP, M_WAITOK);
		error = copyinstr_c(val, (__cheri_cast char * __CAPABILITY)value,
		    len, NULL);
		if (error) {
			free(value, M_TEMP);
			goto done;
		}
#ifdef MAC
		error = mac_kenv_check_set(td->td_ucred, name, value);
		if (error == 0)
#endif
			kern_setenv(name, value);
		free(value, M_TEMP);
		break;
	case KENV_UNSET:
#ifdef MAC
		error = mac_kenv_check_unset(td->td_ucred, name);
		if (error)
			goto done;
#endif
		error = kern_unsetenv(name);
		if (error)
			error = ENOENT;
		break;
	default:
		error = EINVAL;
		break;
	}
done:
	free(name, M_TEMP);
	return (error);
}

/*
 * Populate the initial kernel environment.
 *
 * This is called very early in MD startup, either to provide a copy of the
 * environment obtained from a boot loader, or to provide an empty buffer into
 * which MD code can store an initial environment using kern_setenv() calls.
 *
 * When a copy of an initial environment is passed in, we start by scanning that
 * env for overrides to the compiled-in envmode and hintmode variables.
 *
 * If the global envmode is 1, the environment is initialized from the global
 * static_env[], regardless of the arguments passed.  This implements the env
 * keyword described in config(5).  In this case env_pos is set to env_len,
 * causing kern_setenv() to return -1 (if len > 0) or panic (if len == 0) until
 * the dynamic environment is available.  The envmode and static_env variables
 * are defined in env.c which is generated by config(8).
 *
 * If len is non-zero, the caller is providing an empty buffer.  The caller will
 * subsequently use kern_setenv() to add up to len bytes of initial environment
 * before the dynamic environment is available.
 *
 * If len is zero, the caller is providing a pre-loaded buffer containing
 * environment strings.  Additional strings cannot be added until the dynamic
 * environment is available.  The memory pointed to must remain stable at least
 * until sysinit runs init_dynamic_kenv().  If no initial environment is
 * available from the boot loader, passing a NULL pointer allows the static_env
 * to be installed if it is configured.
 */
void
init_static_kenv(char *buf, size_t len)
{
	char *cp;
	
	for (cp = buf; cp != NULL && cp[0] != '\0'; cp += strlen(cp) + 1) {
		if (strcmp(cp, "static_env.disabled=1") == 0)
			envmode = 0;
		if (strcmp(cp, "static_hints.disabled=1") == 0)
			hintmode = 0;
	}

	if (envmode == 1) {
		kern_envp = static_env;
		env_len = len;
		env_pos = len;
	} else {
		kern_envp = buf;
		env_len = len;
		env_pos = 0;
	}
}

/*
 * Setup the dynamic kernel environment.
 */
static void
init_dynamic_kenv(void *data __unused)
{
	char *cp, *cpnext;
	size_t len;
	int i;

	kenvp = malloc((KENV_SIZE + 1) * sizeof(char *), M_KENV,
		M_WAITOK | M_ZERO);
	i = 0;
	if (kern_envp && *kern_envp != '\0') {
		for (cp = kern_envp; cp != NULL; cp = cpnext) {
			cpnext = kernenv_next(cp);
			len = strlen(cp) + 1;
			if (len > KENV_MNAMELEN + 1 + KENV_MVALLEN + 1) {
				printf(
				"WARNING: too long kenv string, ignoring %s\n",
				    cp);
				continue;
			}
			if (i < KENV_SIZE) {
				kenvp[i] = malloc(len, M_KENV, M_WAITOK);
				strcpy(kenvp[i++], cp);
				memset(cp, 0, strlen(cp));
			} else
				printf(
				"WARNING: too many kenv strings, ignoring %s\n",
				    cp);
		}
	}
	kenvp[i] = NULL;

	mtx_init(&kenv_lock, "kernel environment", NULL, MTX_DEF);
	dynamic_kenv = 1;
}
SYSINIT(kenv, SI_SUB_KMEM, SI_ORDER_ANY, init_dynamic_kenv, NULL);

void
freeenv(char *env)
{

	if (dynamic_kenv && env != NULL) {
		memset(env, 0, strlen(env));
		free(env, M_KENV);
	}
}

/*
 * Internal functions for string lookup.
 */
static char *
_getenv_dynamic(const char *name, int *idx)
{
	char *cp;
	int len, i;

	mtx_assert(&kenv_lock, MA_OWNED);
	len = strlen(name);
	for (cp = kenvp[0], i = 0; cp != NULL; cp = kenvp[++i]) {
		if ((strncmp(cp, name, len) == 0) &&
		    (cp[len] == '=')) {
			if (idx != NULL)
				*idx = i;
			return (cp + len + 1);
		}
	}
	return (NULL);
}

static char *
_getenv_static(const char *name)
{
	char *cp, *ep;
	int len;

	for (cp = kern_envp; cp != NULL; cp = kernenv_next(cp)) {
		for (ep = cp; (*ep != '=') && (*ep != 0); ep++)
			;
		if (*ep != '=')
			continue;
		len = ep - cp;
		ep++;
		if (!strncmp(name, cp, len) && name[len] == 0)
			return (ep);
	}
	return (NULL);
}

/*
 * Look up an environment variable by name.
 * Return a pointer to the string if found.
 * The pointer has to be freed with freeenv()
 * after use.
 */
char *
kern_getenv(const char *name)
{
	char buf[KENV_MNAMELEN + 1 + KENV_MVALLEN + 1];
	char *ret;

	if (dynamic_kenv) {
		if (getenv_string(name, buf, sizeof(buf))) {
			ret = strdup(buf, M_KENV);
		} else {
			ret = NULL;
			WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
			    "getenv");
		}
	} else
		ret = _getenv_static(name);
	return (ret);
}

/*
 * Test if an environment variable is defined.
 */
int
testenv(const char *name)
{
	char *cp;

	if (dynamic_kenv) {
		mtx_lock(&kenv_lock);
		cp = _getenv_dynamic(name, NULL);
		mtx_unlock(&kenv_lock);
	} else
		cp = _getenv_static(name);
	if (cp != NULL)
		return (1);
	return (0);
}

static int
setenv_static(const char *name, const char *value)
{
	int len;

	if (env_pos >= env_len)
		return (-1);

	/* Check space for x=y and two nuls */
	len = strlen(name) + strlen(value);
	if (len + 3 < env_len - env_pos) {
		len = sprintf(&kern_envp[env_pos], "%s=%s", name, value);
		env_pos += len+1;
		kern_envp[env_pos] = '\0';
		return (0);
	} else
		return (-1);

}

/*
 * Set an environment variable by name.
 */
int
kern_setenv(const char *name, const char *value)
{
	char *buf, *cp, *oldenv;
	int namelen, vallen, i;

	if (dynamic_kenv == 0 && env_len > 0)
		return (setenv_static(name, value));

	KENV_CHECK;

	namelen = strlen(name) + 1;
	if (namelen > KENV_MNAMELEN + 1)
		return (-1);
	vallen = strlen(value) + 1;
	if (vallen > KENV_MVALLEN + 1)
		return (-1);
	buf = malloc(namelen + vallen, M_KENV, M_WAITOK);
	sprintf(buf, "%s=%s", name, value);

	mtx_lock(&kenv_lock);
	cp = _getenv_dynamic(name, &i);
	if (cp != NULL) {
		oldenv = kenvp[i];
		kenvp[i] = buf;
		mtx_unlock(&kenv_lock);
		free(oldenv, M_KENV);
	} else {
		/* We add the option if it wasn't found */
		for (i = 0; (cp = kenvp[i]) != NULL; i++)
			;

		/* Bounds checking */
		if (i < 0 || i >= KENV_SIZE) {
			free(buf, M_KENV);
			mtx_unlock(&kenv_lock);
			return (-1);
		}

		kenvp[i] = buf;
		kenvp[i + 1] = NULL;
		mtx_unlock(&kenv_lock);
	}
	return (0);
}

/*
 * Unset an environment variable string.
 */
int
kern_unsetenv(const char *name)
{
	char *cp, *oldenv;
	int i, j;

	KENV_CHECK;

	mtx_lock(&kenv_lock);
	cp = _getenv_dynamic(name, &i);
	if (cp != NULL) {
		oldenv = kenvp[i];
		for (j = i + 1; kenvp[j] != NULL; j++)
			kenvp[i++] = kenvp[j];
		kenvp[i] = NULL;
		mtx_unlock(&kenv_lock);
		memset(oldenv, 0, strlen(oldenv));
		free(oldenv, M_KENV);
		return (0);
	}
	mtx_unlock(&kenv_lock);
	return (-1);
}

/*
 * Return a string value from an environment variable.
 */
int
getenv_string(const char *name, char *data, int size)
{
	char *cp;

	if (dynamic_kenv) {
		mtx_lock(&kenv_lock);
		cp = _getenv_dynamic(name, NULL);
		if (cp != NULL)
			strlcpy(data, cp, size);
		mtx_unlock(&kenv_lock);
	} else {
		cp = _getenv_static(name);
		if (cp != NULL)
			strlcpy(data, cp, size);
	}
	return (cp != NULL);
}

/*
 * Return an integer value from an environment variable.
 */
int
getenv_int(const char *name, int *data)
{
	quad_t tmp;
	int rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (int) tmp;
	return (rval);
}

/*
 * Return an unsigned integer value from an environment variable.
 */
int
getenv_uint(const char *name, unsigned int *data)
{
	quad_t tmp;
	int rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (unsigned int) tmp;
	return (rval);
}

/*
 * Return an int64_t value from an environment variable.
 */
int
getenv_int64(const char *name, int64_t *data)
{
	quad_t tmp;
	int64_t rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (int64_t) tmp;
	return (rval);
}

/*
 * Return an uint64_t value from an environment variable.
 */
int
getenv_uint64(const char *name, uint64_t *data)
{
	quad_t tmp;
	uint64_t rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (uint64_t) tmp;
	return (rval);
}

/*
 * Return a long value from an environment variable.
 */
int
getenv_long(const char *name, long *data)
{
	quad_t tmp;
	int rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (long) tmp;
	return (rval);
}

/*
 * Return an unsigned long value from an environment variable.
 */
int
getenv_ulong(const char *name, unsigned long *data)
{
	quad_t tmp;
	int rval;

	rval = getenv_quad(name, &tmp);
	if (rval)
		*data = (unsigned long) tmp;
	return (rval);
}

/*
 * Return a quad_t value from an environment variable.
 */
int
getenv_quad(const char *name, quad_t *data)
{
	char	value[KENV_MNAMELEN + 1 + KENV_MVALLEN + 1];
	char	*vtp;
	quad_t	iv;

	if (!getenv_string(name, value, sizeof(value)))
		return (0);
	iv = strtoq(value, &vtp, 0);
	if (vtp == value || (vtp[0] != '\0' && vtp[1] != '\0'))
		return (0);
	switch (vtp[0]) {
	case 't': case 'T':
		iv *= 1024;
	case 'g': case 'G':
		iv *= 1024;
	case 'm': case 'M':
		iv *= 1024;
	case 'k': case 'K':
		iv *= 1024;
	case '\0':
		break;
	default:
		return (0);
	}
	*data = iv;
	return (1);
}

/*
 * Find the next entry after the one which (cp) falls within, return a
 * pointer to its start or NULL if there are no more.
 */
static char *
kernenv_next(char *cp)
{

	if (cp != NULL) {
		while (*cp != 0)
			cp++;
		cp++;
		if (*cp == 0)
			cp = NULL;
	}
	return (cp);
}

void
tunable_int_init(void *data)
{
	struct tunable_int *d = (struct tunable_int *)data;

	TUNABLE_INT_FETCH(d->path, d->var);
}

void
tunable_long_init(void *data)
{
	struct tunable_long *d = (struct tunable_long *)data;

	TUNABLE_LONG_FETCH(d->path, d->var);
}

void
tunable_ulong_init(void *data)
{
	struct tunable_ulong *d = (struct tunable_ulong *)data;

	TUNABLE_ULONG_FETCH(d->path, d->var);
}

void
tunable_int64_init(void *data)
{
	struct tunable_int64 *d = (struct tunable_int64 *)data;

	TUNABLE_INT64_FETCH(d->path, d->var);
}

void
tunable_uint64_init(void *data)
{
	struct tunable_uint64 *d = (struct tunable_uint64 *)data;

	TUNABLE_UINT64_FETCH(d->path, d->var);
}

void
tunable_quad_init(void *data)
{
	struct tunable_quad *d = (struct tunable_quad *)data;

	TUNABLE_QUAD_FETCH(d->path, d->var);
}

void
tunable_str_init(void *data)
{
	struct tunable_str *d = (struct tunable_str *)data;

	TUNABLE_STR_FETCH(d->path, d->var, d->size);
}
