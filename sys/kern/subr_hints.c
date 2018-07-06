/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2000,2001 Peter Wemm <peter@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/bus.h>

/*
 * Access functions for device resources.
 */

static int checkmethod = 1;
static int use_kenv;
static char *hintp;

/*
 * Define kern.hintmode sysctl, which only accept value 2, that cause to
 * switch from Static KENV mode to Dynamic KENV. So systems that have hints
 * compiled into kernel will be able to see/modify KENV (and hints too).
 */

static int
sysctl_hintmode(SYSCTL_HANDLER_ARGS)
{
	const char *cp;
	char *line, *eq;
	int eqidx, error, from_kenv, i, value;

	from_kenv = 0;
	cp = kern_envp;
	value = hintmode;

	/* Fetch candidate for new hintmode value */
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || req->newptr == NULL)
		return (error);

	if (value != 2)
		/* Only accept swithing to hintmode 2 */
		return (EINVAL);

	/* Migrate from static to dynamic hints */
	switch (hintmode) {
	case 0:
		if (dynamic_kenv) {
			/*
			 * Already here. But assign hintmode to 2, to not
			 * check it in the future.
			 */
			hintmode = 2;
			return (0);
		}
		from_kenv = 1;
		cp = kern_envp;
		break;
	case 1:
		cp = static_hints;
		break;
	case 2:
		/* Nothing to do, hintmode already 2 */
		return (0);
	}

	while (cp) {
		i = strlen(cp);
		if (i == 0)
			break;
		if (from_kenv) {
			if (strncmp(cp, "hint.", 5) != 0)
				/* kenv can have not only hints */
				continue;
		}
		eq = strchr(cp, '=');
		if (eq == NULL)
			/* Bad hint value */
			continue;
		eqidx = eq - cp;

		line = malloc(i+1, M_TEMP, M_WAITOK);
		strcpy(line, cp);
		line[eqidx] = '\0';
		kern_setenv(line, line + eqidx + 1);
		free(line, M_TEMP);
		cp += i + 1;
	}

	hintmode = value;
	use_kenv = 1;
	return (0);
}

SYSCTL_PROC(_kern, OID_AUTO, hintmode, CTLTYPE_INT|CTLFLAG_RW,
    &hintmode, 0, sysctl_hintmode, "I", "Get/set current hintmode");

/*
 * Evil wildcarding resource string lookup.
 * This walks the supplied env string table and returns a match.
 * The start point can be remembered for incremental searches.
 */
static int
res_find(int *line, int *startln,
    const char *name, int *unit, const char *resname, const char *value,
    const char **ret_name, int *ret_namelen, int *ret_unit,
    const char **ret_resname, int *ret_resnamelen, const char **ret_value)
{
	int n = 0, hit, i = 0;
	char r_name[32];
	int r_unit;
	char r_resname[32];
	char r_value[128];
	const char *s, *cp;
	char *p;

	if (checkmethod) {
		hintp = NULL;

		switch (hintmode) {
		case 0:		/* loader hints in environment only */
			break;
		case 1:		/* static hints only */
			hintp = static_hints;
			checkmethod = 0;
			break;
		case 2:		/* fallback mode */
			if (dynamic_kenv) {
				mtx_lock(&kenv_lock);
				cp = kenvp[0];
				for (i = 0; cp != NULL; cp = kenvp[++i]) {
					if (!strncmp(cp, "hint.", 5)) {
						use_kenv = 1;
						checkmethod = 0;
						break;
					}
				}
				mtx_unlock(&kenv_lock);
			} else {
				cp = kern_envp;
				while (cp) {
					if (strncmp(cp, "hint.", 5) == 0) {
						cp = NULL;
						hintp = kern_envp;
						break;
					}
					while (*cp != '\0')
						cp++;
					cp++;
					if (*cp == '\0') {
						cp = NULL;
						hintp = static_hints;
						break;
					}
				}
			}
			break;
		default:
			break;
		}
		if (hintp == NULL) {
			if (dynamic_kenv) {
				use_kenv = 1;
				checkmethod = 0;
			} else
				hintp = kern_envp;
		}
	}

	if (use_kenv) {
		mtx_lock(&kenv_lock);
		i = 0;
		cp = kenvp[0];
		if (cp == NULL) {
			mtx_unlock(&kenv_lock);
			return (ENOENT);
		}
	} else
		cp = hintp;
	while (cp) {
		hit = 1;
		(*line)++;
		if (strncmp(cp, "hint.", 5) != 0)
			hit = 0;
		else
			n = sscanf(cp, "hint.%32[^.].%d.%32[^=]=%127s",
			    r_name, &r_unit, r_resname, r_value);
		if (hit && n != 4) {
			printf("CONFIG: invalid hint '%s'\n", cp);
			p = strchr(cp, 'h');
			*p = 'H';
			hit = 0;
		}
		if (hit && startln && *startln >= 0 && *line < *startln)
			hit = 0;
		if (hit && name && strcmp(name, r_name) != 0)
			hit = 0;
		if (hit && unit && *unit != r_unit)
			hit = 0;
		if (hit && resname && strcmp(resname, r_resname) != 0)
			hit = 0;
		if (hit && value && strcmp(value, r_value) != 0)
			hit = 0;
		if (hit)
			break;
		if (use_kenv) {
			cp = kenvp[++i];
			if (cp == NULL)
				break;
		} else {
			while (*cp != '\0')
				cp++;
			cp++;
			if (*cp == '\0') {
				cp = NULL;
				break;
			}
		}
	}
	if (use_kenv)
		mtx_unlock(&kenv_lock);
	if (cp == NULL)
		return ENOENT;

	s = cp;
	/* This is a bit of a hack, but at least is reentrant */
	/* Note that it returns some !unterminated! strings. */
	s = strchr(s, '.') + 1;		/* start of device */
	if (ret_name)
		*ret_name = s;
	s = strchr(s, '.') + 1;		/* start of unit */
	if (ret_namelen && ret_name)
		*ret_namelen = s - *ret_name - 1; /* device length */
	if (ret_unit)
		*ret_unit = r_unit;
	s = strchr(s, '.') + 1;		/* start of resname */
	if (ret_resname)
		*ret_resname = s;
	s = strchr(s, '=') + 1;		/* start of value */
	if (ret_resnamelen && ret_resname)
		*ret_resnamelen = s - *ret_resname - 1; /* value len */
	if (ret_value)
		*ret_value = s;
	if (startln)			/* line number for anchor */
		*startln = *line + 1;
	return 0;
}

/*
 * Search all the data sources for matches to our query.  We look for
 * dynamic hints first as overrides for static or fallback hints.
 */
static int
resource_find(int *line, int *startln,
    const char *name, int *unit, const char *resname, const char *value,
    const char **ret_name, int *ret_namelen, int *ret_unit,
    const char **ret_resname, int *ret_resnamelen, const char **ret_value)
{
	int i;
	int un;

	*line = 0;

	/* Search for exact unit matches first */
	i = res_find(line, startln, name, unit, resname, value,
	    ret_name, ret_namelen, ret_unit, ret_resname, ret_resnamelen,
	    ret_value);
	if (i == 0)
		return 0;
	if (unit == NULL)
		return ENOENT;
	/* If we are still here, search for wildcard matches */
	un = -1;
	i = res_find(line, startln, name, &un, resname, value,
	    ret_name, ret_namelen, ret_unit, ret_resname, ret_resnamelen,
	    ret_value);
	if (i == 0)
		return 0;
	return ENOENT;
}

int
resource_int_value(const char *name, int unit, const char *resname, int *result)
{
	int error;
	const char *str;
	char *op;
	unsigned long val;
	int line;

	line = 0;
	error = resource_find(&line, NULL, name, &unit, resname, NULL,
	    NULL, NULL, NULL, NULL, NULL, &str);
	if (error)
		return error;
	if (*str == '\0') 
		return EFTYPE;
	val = strtoul(str, &op, 0);
	if (*op != '\0') 
		return EFTYPE;
	*result = val;
	return 0;
}

int
resource_long_value(const char *name, int unit, const char *resname,
    long *result)
{
	int error;
	const char *str;
	char *op;
	unsigned long val;
	int line;

	line = 0;
	error = resource_find(&line, NULL, name, &unit, resname, NULL,
	    NULL, NULL, NULL, NULL, NULL, &str);
	if (error)
		return error;
	if (*str == '\0') 
		return EFTYPE;
	val = strtoul(str, &op, 0);
	if (*op != '\0') 
		return EFTYPE;
	*result = val;
	return 0;
}

int
resource_string_value(const char *name, int unit, const char *resname,
    const char **result)
{
	int error;
	const char *str;
	int line;

	line = 0;
	error = resource_find(&line, NULL, name, &unit, resname, NULL,
	    NULL, NULL, NULL, NULL, NULL, &str);
	if (error)
		return error;
	*result = str;
	return 0;
}

/*
 * This is a bit nasty, but allows us to not modify the env strings.
 */
static const char *
resource_string_copy(const char *s, int len)
{
	static char stringbuf[256];
	static int offset = 0;
	const char *ret;

	if (len == 0)
		len = strlen(s);
	if (len > 255)
		return NULL;
	if ((offset + len + 1) > 255)
		offset = 0;
	bcopy(s, &stringbuf[offset], len);
	stringbuf[offset + len] = '\0';
	ret = &stringbuf[offset];
	offset += len + 1;
	return ret;
}

/*
 * err = resource_find_match(&anchor, &name, &unit, resname, value)
 * Iteratively fetch a list of devices wired "at" something
 * res and value are restrictions.  eg: "at", "scbus0".
 * For practical purposes, res = required, value = optional.
 * *name and *unit are set.
 * set *anchor to zero before starting.
 */
int
resource_find_match(int *anchor, const char **name, int *unit,
    const char *resname, const char *value)
{
	const char *found_name;
	int found_namelen;
	int found_unit;
	int ret;
	int newln;

	newln = *anchor;
	ret = resource_find(anchor, &newln, NULL, NULL, resname, value,
	    &found_name, &found_namelen, &found_unit, NULL, NULL, NULL);
	if (ret == 0) {
		*name = resource_string_copy(found_name, found_namelen);
		*unit = found_unit;
	}
	*anchor = newln;
	return ret;
}


/*
 * err = resource_find_dev(&anchor, name, &unit, res, value);
 * Iterate through a list of devices, returning their unit numbers.
 * res and value are optional restrictions.  eg: "at", "scbus0".
 * *unit is set to the value.
 * set *anchor to zero before starting.
 */
int
resource_find_dev(int *anchor, const char *name, int *unit,
    const char *resname, const char *value)
{
	int found_unit;
	int newln;
	int ret;

	newln = *anchor;
	ret = resource_find(anchor, &newln, name, NULL, resname, value,
	    NULL, NULL, &found_unit, NULL, NULL, NULL);
	if (ret == 0) {
		*unit = found_unit;
	}
	*anchor = newln;
	return ret;
}

/*
 * Check to see if a device is disabled via a disabled hint.
 */
int
resource_disabled(const char *name, int unit)
{
	int error, value;

	error = resource_int_value(name, unit, "disabled", &value);
	if (error)
	       return (0);
	return (value);
}

/*
 * Clear a value associated with a device by removing it from
 * the kernel environment.  This only removes a hint for an
 * exact unit.
 */
int
resource_unset_value(const char *name, int unit, const char *resname)
{
	char varname[128];
	const char *retname, *retvalue;
	int error, line;
	size_t len;

	line = 0;
	error = resource_find(&line, NULL, name, &unit, resname, NULL,
	    &retname, NULL, NULL, NULL, NULL, &retvalue);
	if (error)
		return (error);

	retname -= strlen("hint.");
	len = retvalue - retname - 1;
	if (len > sizeof(varname) - 1)
		return (ENAMETOOLONG);
	memcpy(varname, retname, len);
	varname[len] = '\0';
	return (kern_unsetenv(varname));
}
