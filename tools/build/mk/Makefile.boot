# $FreeBSD$

CFLAGS+=	-I${WORLDTMP}/legacy/usr/include
DPADD+=		${WORLDTMP}/legacy/usr/lib/libegacy.a
LDADD+=		-legacy
LDFLAGS+=	-L${WORLDTMP}/legacy/usr/lib

BUILD_TOOLS_CFLAGS=${CFLAGS}
BUILD_TOOLS_LDFLAGS=${LDFLAGS}

# we do not want to capture dependencies referring to the above
UPDATE_DEPENDFILE= no
