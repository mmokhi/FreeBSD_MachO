.include <bsd.own.mk>


MAIN_SOURCE_LOCATION= ${.CURDIR}

.PATH: ${MAIN_SOURCE_LOCATION}

KMOD=	macho
SRCS=	imgact_macho.c	macho_macros.h imgact_macho.h macho_machdep.c macho_machdep.h \
		vnode_if.h vnode_if_typedef.h vnode_if_newproto.h
CFLAGS+= -I${.CURDIR} -DMACHO_DEBUG

.include <bsd.kmod.mk>

