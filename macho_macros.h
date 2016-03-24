/*-
 * Copyright (c) 2016 Mahdi Mokhtari.
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
 *
 */

#ifndef MACHO_MACROS_H_
#define MACHO_MACROS_H_

/**************** MachO Fat Header ****************/

#define MACHO_FAT_MAGIC	0xcafebabe

#define	MACHO_CPU_ARCH_MASK 0xff000000		/* mask for architecture bits */
#define MACHO_CPU_ARCH_ABI64 0x01000000		/* 64 bit ABI */

#define	MACHO_CPU_TYPE_ANY		(~0)
#define	MACHO_CPU_TYPE_VAX		1
#define	MACHO_CPU_TYPE_MC680x0	6
#define	MACHO_CPU_TYPE_I386		7
#define	MACHO_CPU_TYPE_MIPS		8
#define	MACHO_CPU_TYPE_MC98000	10
#define	MACHO_CPU_TYPE_HPPA		11
#define	MACHO_CPU_TYPE_ARM		12
#define	MACHO_CPU_TYPE_MC88000	13
#define	MACHO_CPU_TYPE_SPARC	14
#define	MACHO_CPU_TYPE_I860		15
#define	MACHO_CPU_TYPE_ALPHA	16
#define	MACHO_CPU_TYPE_POWERPC	18
#define	MACHO_CPU_TYPE_LAST		19
#define	MACHO_CPU_TYPE_NONE		0
#define MACHO_CPU_TYPE_SKIPPED(X) (X == 2 || X == 3 || X == 4 || X == 5 || X == 9 || X == 17)
#define MACHO_CPU_TYPE_VALID(X) (X != MACHO_CPU_TYPE_NONE && X < MACHO_CPU_TYPE_LAST && ! MACHO_CPU_TYPE_SKIPPED(X))

#define MACHO_CPU_SUBTYPE_MASK	0xff000000	/* mask for feature flags */
#define MACHO_CPU_SUBTYPE_LIB64	0x80000000	/* 64 bit libraries */

#define	MACHO_CPU_SUBTYPE_MULTIPLE			(~0)
#define	MACHO_CPU_SUBTYPE_LITTLE_ENDIAN		0
#define	MACHO_CPU_SUBTYPE_BIG_ENDIAN		1

/* m68k */
#define	MACHO_CPU_SUBTYPE_MC680x0_ALL		1
#define	MACHO_CPU_SUBTYPE_MC68030		1
#define	MACHO_CPU_SUBTYPE_MC68040		2
#define	MACHO_CPU_SUBTYPE_MC68030_ONLY		3

/* x86 */
#define	MACHO_CPU_SUBTYPE_I386_ALL	3
#define	MACHO_CPU_SUBTYPE_386		3
#define	MACHO_CPU_SUBTYPE_486		4
#define	MACHO_CPU_SUBTYPE_486SX		(4 + 128)
#define	MACHO_CPU_SUBTYPE_586		5
#define	MACHO_CPU_SUBTYPE_INTEL(f, m)	((f) + ((m) << 4))
#define	MACHO_CPU_SUBTYPE_PENT		MACHO_CPU_SUBTYPE_INTEL(5, 0)
#define	MACHO_CPU_SUBTYPE_PENTPRO	MACHO_CPU_SUBTYPE_INTEL(6, 1)
#define	MACHO_CPU_SUBTYPE_PENTII_M3	MACHO_CPU_SUBTYPE_INTEL(6, 3)
#define	MACHO_CPU_SUBTYPE_PENTII_M5	MACHO_CPU_SUBTYPE_INTEL(6, 5)
#define	MACHO_CPU_SUBTYPE_INTEL_FAMILY(x)	((x) & 15)
#define	MACHO_CPU_SUBTYPE_INTEL_FAMILY_MAX	15
#define	MACHO_CPU_SUBTYPE_INTEL_MODEL(x)	((x) >> 4)
#define	MACHO_CPU_SUBTYPE_INTEL_MODEL_ALL	0
/* PowerPC */
#define	MACHO_CPU_SUBTYPE_POWERPC_ALL		 0
#define	MACHO_CPU_SUBTYPE_POWERPC_601		 1
#define	MACHO_CPU_SUBTYPE_POWERPC_602		 2
#define	MACHO_CPU_SUBTYPE_POWERPC_603		 3
#define	MACHO_CPU_SUBTYPE_POWERPC_603e		 4
#define	MACHO_CPU_SUBTYPE_POWERPC_603ev		 5
#define	MACHO_CPU_SUBTYPE_POWERPC_604		 6
#define	MACHO_CPU_SUBTYPE_POWERPC_604e		 7
#define	MACHO_CPU_SUBTYPE_POWERPC_620		 8
#define	MACHO_CPU_SUBTYPE_POWERPC_750		 9
#define	MACHO_CPU_SUBTYPE_POWERPC_7400		10
#define	MACHO_CPU_SUBTYPE_POWERPC_7450		11

/**************** MachO Header ****************/
#define	MACHO_MH_MAGIC	0xfeedface

/* Object header filetype */
#define	MACHO_MH_OBJECT	0x1
#define	MACHO_MH_EXECUTE	0x2
#define	MACHO_MH_FVMLIB	0x3
#define	MACHO_MH_CORE		0x4
#define	MACHO_MH_PRELOAD	0x5
#define	MACHO_MH_DYLIB		0x6
#define	MACHO_MH_DYLINKER	0x7
#define	MACHO_MH_BUNDLE	0x8

/* Object header flags */
#define	MACHO_MH_NOUNDEFS	0x001
#define	MACHO_MH_INCRLINK	0x002
#define	MACHO_MH_DYLDLINK	0x004
#define	MACHO_MH_BINDATLOAD	0x008
#define	MACHO_MH_PREBOUND	0x010
#define	MACHO_MH_SPLIT_SEGS	0x020
#define	MACHO_MH_LAZY_INIT	0x040
#define	MACHO_MH_TWOLEVEL	0x080
#define	MACHO_MH_FORCE_FLAT	0x100

/**************** MachO Load Command ****************/
#define	MACHO_LC_SEGMENT	0x01
#define	MACHO_LC_SYMTAB		0x02
#define	MACHO_LC_SYMSEG		0x03
#define	MACHO_LC_THREAD		0x04
#define	MACHO_LC_UNIXTHREAD	0x05
#define	MACHO_LC_LOADFVMLIB	0x06
#define	MACHO_LC_IDFVMLIB	0x07
#define	MACHO_LC_IDENT		0x08
#define	MACHO_LC_FVMFILE	0x09
#define	MACHO_LC_PREPAGE	0x0a
#define	MACHO_LC_DYSYMTAB	0x0b
#define	MACHO_LC_LOAD_DYLIB	0x0c
#define	MACHO_LC_ID_DYLIB	0x0d
#define	MACHO_LC_LOAD_DYLINKER	0x0e
#define	MACHO_LC_ID_DYLINKER	0x0f
#define	MACHO_LC_PREBOUND_DYLIB	0x10
#define	MACHO_LC_ROUTINES	0x11
#define	MACHO_LC_SUB_FRAMEWORK	0x12
#define	MACHO_LC_SUB_UMBRELLA	0x13
#define	MACHO_LC_SUB_CLIENT	0x14

/**************** MachO Segment Command ****************/
#define	MACHO_SG_HIGHVM		0x1
#define	MACHO_SG_FVMLIB		0x2
#define	MACHO_SG_NORELOC	0x4

#endif /* MACHO_MACROS_H_ */
