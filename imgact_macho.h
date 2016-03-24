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

#ifndef _SYS_IMGACT_MACHO_H_
#define	_SYS_IMGACT_MACHO_H_

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

#include <sys/sysent.h>
#include <sys/syscall.h>

#include "macho_machdep.h"
#include "macho_macros.h"

typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;
typedef uint32_t integer_t;
typedef integer_t cpu_threadtype_t;

#if defined(__i386__) || defined(__amd64__)
#define macho_current_cpu ((cpu_type_t) MACHO_CPU_TYPE_I386)
#else
#error "port me !"
#endif

struct macho_fat_header {
	uint32_t magic; /* FAT_MAGIC */
	uint32_t nfat_arch; /* number of structs that follow */
};

struct macho_fat_arch {
	cpu_type_t cputype; /* cpu specifier (int) */
	cpu_subtype_t cpusubtype; /* machine specifier (int) */
	uint32_t offset; /* file offset to this object file */
	uint32_t size; /* size of this object file */
	uint32_t align; /* alignment as a power of 2 */
};

struct macho_mach_header {
	uint32_t magic; /* mach magic number identifier */
	cpu_type_t cputype; /* cpu specifier */
	cpu_subtype_t cpusubtype; /* machine specifier */
	uint32_t filetype; /* type of file */
	uint32_t ncmds; /* number of load commands */
	uint32_t sizeofcmds; /* the size of all the load commands */
	uint32_t flags; /* flags */
};

struct macho_load_command {
	uint32_t cmd; /* type of load command */
	uint32_t cmdsize; /* total size of command in bytes */
};

union macho_lc_str {
	uint32_t offset; /* offset to the string */
#ifndef __LP64__
	char *ptr; /* pointer to the string */
#endif
};

struct macho_segment_command {
	uint32_t cmd; /* LC_SEGMENT */
	uint32_t cmdsize; /* includes sizeof section structs */
	char segname[16]; /* segment name */
	uint32_t vmaddr; /* memory address of this segment */
	uint32_t vmsize; /* memory size of this segment */
	uint32_t fileoff; /* file offset of this segment */
	uint32_t filesize; /* amount to map from the file */
	/*vm_prot_t*/uint32_t maxprot; /* maximum VM protection */
	/*vm_prot_t*/uint32_t initprot; /* initial VM protection */
	uint32_t nsects; /* number of sections in segment */
	uint32_t flags; /* flags */
};

struct macho_section {
	char sectname[16]; /* name of this section */
	char segname[16]; /* segment this section goes in */
	uint32_t addr; /* memory address of this section */
	uint32_t size; /* size in bytes of this section */
	uint32_t offset; /* file offset of this section */
	uint32_t align; /* section alignment (power of 2) */
	uint32_t reloff; /* file offset of relocation entries */
	uint32_t nreloc; /* number of relocation entries */
	uint32_t flags; /* flags (section type and attributes)*/
	uint32_t reserved1; /* reserved (for offset or index) */
	uint32_t reserved2; /* reserved (for count or sizeof) */
};

struct macho_dylib {
	union macho_lc_str name; /* library's path name */
	uint32_t timestamp; /* library's build time stamp */
	uint32_t current_version; /* library's current version number */
	uint32_t compatibility_version; /* library's compatibility vers number*/
};

struct macho_dylib_command {
	uint32_t cmd; /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB, LC_REEXPORT_DYLIB */
	uint32_t cmdsize; /* includes pathname string */
	struct macho_dylib dylib; /* the library identification */
};

struct macho_dylinker_command {
	uint32_t cmd; /* LC_ID_DYLINKER, LC_LOAD_DYLINKER, LC_DYLD_ENVIRONMENT */
	uint32_t cmdsize; /* includes pathname string */
	union macho_lc_str name; /* dynamic linker's path name */
};

struct macho_thread_command {
	uint32_t cmd; /* LC_THREAD or  LC_UNIXTHREAD */
	uint32_t cmdsize; /* total size of this command */
	/* XXX FIXME below commented in newest XNU */
	uint32_t flavor; /* flavor of thread state */
	uint32_t count; /* count of longs in thread state */
/* struct XXX_thread_state state   thread state for this flavor */
/* ... */
};

struct entry_point_command {
	uint32_t cmd; /* LC_MAIN only used in MH_EXECUTE filetypes */
	uint32_t cmdsize; /* 24 */
	uint64_t entryoff; /* file (__TEXT) offset of main() */
	uint64_t stacksize;/* if not zero, initial stack size */
};

#ifdef _KERNEL
extern struct sysentvec macho_freebsd_sysvec;
u_long macho_thread_entry(struct macho_thread_command *tc);
#endif /* _KERNEL */

#endif /* !_SYS_IMGACT_MACHO_H_ */
