/*
 * Copyright (c) 1994 University of Maryland
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of U.M. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  U.M. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * U.M. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL U.M.
 * BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: James da Silva, Systems Design and Analysis Group
 *			   Computer Science Department
 *			   University of Maryland at College Park
 */
/*
 * crunched_main.c - main program for crunched binaries, it branches to a
 * 	particular subprogram based on the value of argv[0].  Also included
 *	is a little program invoked when the crunched binary is called via
 *	its EXECNAME.  This one prints out the list of compiled-in binaries,
 *	or calls one of them based on argv[1].   This allows the testing of
 *	the crunched binary without creating all the links.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/auxv.h>
#include <sys/sysctl.h>

struct stub {
    char *name;
    int (*f)();
};

extern char *__progname;
extern struct stub entry_points[];

static void crunched_usage(void);


static struct stub* find_entry_point(const char* basename)
{
    struct stub *ep;

    for(ep=entry_points; ep->name != NULL; ep++)
	if(!strcmp(basename, ep->name)) break;

    return ep;
}

static const char* get_basename(const char* exe_path)
{
    const char *slash;

    slash = strrchr(exe_path, '/');
    return (slash ? slash+1 : exe_path);
}

int
main(int argc, char **argv, char **envp)
{
    struct stub *ep;
    const char *basename = NULL;
    char exe_buf[MAXPATHLEN];

    /*
     * Look at __progname first (this will be set if the crunched binary is
     * invoked directly).
     */
    if (__progname) {
	basename = get_basename(__progname);
	ep = find_entry_point(basename);
    }

    /*
     * Otherwise try to find entry point based on argv[0] (this works for both
     * symlinks as well as hardlinks).
     * However, it does not work when su invokes a crunched shell because it
     * sets argv[0] to _su when invoking the shell. In that case we look at
     * KERN_PROC_PATHNAME. This will only work for hard links to the
     * crunched binary but that should be fine.
     * TODO: is there a way to get the exepath without resolving symlinks?
     */
    if (ep->name == NULL) {
	basename = get_basename(argv[0]);
	ep = find_entry_point(basename);
    }

#ifdef AT_EXECPATH
    /*
     * Try AT_EXECPATH to get the actual binary that was executed.
     * This is needed since su will set argv[0] to -su instead of the shell.
     */
    if (ep->name == NULL) {
	int error = elf_aux_info(AT_EXECPATH, &exe_buf, sizeof(exe_buf));
	if (error == 0) {
	    const char *exe_name = get_basename(exe_buf);
	    /*
	     * Keep using argv[0] if AT_EXECPATH is the crunched binary
	     * so that symlinks to the crunched binary report "not compiled in"
	     * instead of invoking crunched_main().
	     */
	    if (strcmp(exe_name, EXECNAME) != 0) {
		basename = exe_name;
		ep = find_entry_point(basename);
	    }
	} else {
		fprintf(stderr, "elf_aux_info(AT_EXECPATH) got error %d: %s\n", error, strerror(error));
	}
    }
#else
#error "EXPECTED AT_EXECPATH to exist!"
#endif

    /* Finally fall back to using KERN_PROC_PATHNAME */
    /*
     * XXXAR: this does not seem to work correctly since it appears to return
     * the last resolved path for a hardlink rather than the one that was
     * actually used to execute the command.
     */
#if 0
    if (ep->name == NULL) {
	size_t len = sizeof(exe_buf);
	int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	if (sysctl(name, 4, exe_buf, &len, NULL, 0) == 0) {
	    const char *exe_name = get_basename(exe_buf);
	    /*
	     * Keep using argv[0] if KERN_PROC_PATHNAME is the crunched binary
	     * so that symlinks to the crunched binary report "not compiled in"
	     * instead of invoking crunched_main().
	     */
	    if (strcmp(exe_name, EXECNAME) != 0) {
		basename = exe_name;
		ep = find_entry_point(basename);
	    }
	}
    }
#endif

    if (basename == NULL || *basename == '\0')
	crunched_usage();

    if (ep->name)
	return ep->f(argc, argv, envp);
    else {
	fprintf(stderr, "%s: %s not compiled in\n", EXECNAME, basename);
	crunched_usage();
    }
}


int
crunched_main(int argc, char **argv, char **envp)
{
    char *slash;
    struct stub *ep;
    int columns, len;

    if(argc <= 1)
	crunched_usage();

    slash = strrchr(argv[1], '/');
    __progname = slash? slash+1 : argv[1];

    return main(--argc, ++argv, envp);
}


static void
crunched_usage()
{
    int columns, len;
    struct stub *ep;

    fprintf(stderr, "usage: %s <prog> <args> ..., where <prog> is one of:\n",
	    EXECNAME);
    columns = 0;
    for(ep=entry_points; ep->name != NULL; ep++) {
	len = strlen(ep->name) + 1;
	if(columns+len < 80)
	    columns += len;
	else {
	    fprintf(stderr, "\n");
	    columns = len;
	}
	fprintf(stderr, " %s", ep->name);
    }
    fprintf(stderr, "\n");
    exit(1);
}

/* end of crunched_main.c */
