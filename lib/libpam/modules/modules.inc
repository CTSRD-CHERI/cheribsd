# $FreeBSD$

.include <src.opts.mk>

MODULES		 =
# A few minimal modules that can be used by tools/cheribsdbox
MODULES		+= pam_deny
MODULES		+= pam_nologin
MODULES		+= pam_permit
MODULES		+= pam_rootok
MODULES		+= pam_self
.if !defined(PAM_MINIMAL)
MODULES		+= pam_chroot
MODULES		+= pam_echo
MODULES		+= pam_exec
MODULES		+= pam_ftpusers
MODULES		+= pam_group
MODULES		+= pam_guest
.if ${MK_KERBEROS} != "no"
MODULES		+= pam_krb5
MODULES		+= pam_ksu
.endif
MODULES		+= pam_lastlog
MODULES		+= pam_login_access
MODULES		+= pam_opie
MODULES		+= pam_opieaccess
MODULES		+= pam_passwdqc
.if ${MK_RADIUS_SUPPORT} != "no"
MODULES		+= pam_radius
.endif
MODULES		+= pam_rhosts
MODULES		+= pam_securetty
.if ${MK_OPENSSH} != "no"
MODULES		+= pam_ssh
.endif
MODULES		+= pam_tacplus
MODULES		+= pam_unix
.endif  # !defined(PAM_MINIMAL)
