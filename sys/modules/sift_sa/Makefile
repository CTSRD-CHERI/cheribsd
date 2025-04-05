KMOD=	sift_sa

COMPARTMENT_POLICY=	sift_sa.json

# Use the policy regardless of the kernel.
CHERI_COMPARTMENT_POLICY=yes

SRCS=	sift_sa.c
SRCS+=	sift_sa_private.c
SRCS+=	sift_sa_public.c

.include <bsd.kmod.mk>
