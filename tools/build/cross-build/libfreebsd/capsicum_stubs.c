#include <errno.h>
#include <sys/types.h>
#include <sys/capsicum.h>

int
cap_ioctls_limit(int fd, const cap_ioctl_t *cmds, size_t ncmds) {
	return 0; /* Just pretend that it succeeded */
}

int
cap_fcntls_limit(int fd, uint32_t fcntlrights) {
	return 0; /* Just pretend that it succeeded */
}

int
cap_rights_limit(int fd, const cap_rights_t *rights) {
	return 0; /* Just pretend that it succeeded */
}

int
cap_enter(void) {
	errno = ENOSYS;
	return -1;
}
