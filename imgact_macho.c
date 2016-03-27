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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/pioctl.h>
#include <sys/proc.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sf_buf.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/eventhandler.h>
#include <sys/user.h>
#include <sys/endian.h>

#include <machine/md_var.h>

#include "imgact_macho.h" /* FIXME Should change it to <sys/imgact_macho.h> */

#define	trunc_page_ps(va, ps)	((va) & ~(ps - 1))
#define	round_page_ps(va, ps)	(((va) + (ps - 1)) & ~(ps - 1))
#define	aligned(a, t)	(trunc_page_ps((u_long)(a), sizeof(t)) == (u_long)(a))

#ifdef MACHO_DEBUG
#define printf uprintf
#else
#define printf printf
#endif


static int
macho_fat_extract_arch(struct vnode *vp, const struct macho_fat_header *hdr,
        struct macho_fat_arch *arch);

static int
macho_mach_extract(struct image_params *imgp, const union macho_header *header,
        struct macho_fat_arch *arch, struct macho_mach_header *mach_part);

static int
macho_loadfile(struct proc *p, const char *path, u_long *res_entry, int depth);

static int
macho_load_dyn(struct proc *p, struct macho_load_command *dlcp, int type,
        u_long *res_ent, int depth);

static int
macho_parse_machfile(struct image_params *imgp,
        struct macho_mach_header *header, off_t file_offset, off_t macho_size,
        int depth, u_long *res_ent);

/* XXX borrowed from ELF image activator with little changes. */
static int
macho_map_create_page(vm_map_t map, vm_object_t object,
        vm_ooffset_t macho_start, vm_offset_t start, vm_offset_t end,
        vm_prot_t prot_min, vm_prot_t prot_max);

/* XXX borrowed from ELF image activator with little changes. */
static int
macho_map_align_insert(vm_map_t map, vm_object_t object,
        vm_ooffset_t macho_start, vm_offset_t start, vm_offset_t end,
        vm_prot_t prot_min, vm_prot_t prot_max);

/*
 * XXX XXX
 * I tried to do similar way of what FreeBSD did on Elf, respecting Mach-O standards/Docs.
 * Sure, it can be better.
 */
static int
macho_load_segment(struct image_params *imgp,
        struct macho_segment_command *scp, uint32_t type, off_t macho_start,
        off_t macho_size);

static int
exec_macho_imgact(struct image_params *imgp);

static int
macho_fat_extract_arch(struct vnode *vp, const struct macho_fat_header *hdr,
        struct macho_fat_arch *arch)
{
	int i = 0;
	struct thread *td = curthread;

	/* XXX FIXME try to avoid (or pre-determine instead of) be32toh() here [for `nfat_arch`]*/
	for (i = 0; i < be32toh(hdr->nfat_arch); ++i) {
		int error = vn_rdwr(UIO_READ, vp, arch, sizeof(*arch), sizeof(*hdr)
		        + sizeof(*arch) * i, UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred,
		        NOCRED, NULL, td);
		if (error != 0) {
			printf("vn_rdwr error: %d\n", error);
			return error;
		}

		if (arch->cputype == macho_current_cpu || be32toh(arch->cputype)
		        == macho_current_cpu) {
			/* XXX XXX trying to make it HOST-Endian */
			if(be32toh(arch->cputype) == macho_current_cpu) {
				arch->cputype = be32toh(arch->cputype);
				arch->cpusubtype = be32toh(arch->cpusubtype);
				arch->offset = be32toh(arch->offset);
				arch->size = be32toh(arch->size);
				arch->align = be32toh(arch->align);
			}
			break;
		} else if (!MACHO_CPU_TYPE_VALID(arch->cputype)
		        && !MACHO_CPU_TYPE_VALID(be32toh(arch->cputype))) {
			printf("Invalid CPU_TYPE: 0x%x\n", arch->cputype);
			return -1;
		}
	}

	return (i >= be32toh(hdr->nfat_arch)) ? ENOEXEC : 0;
}

static int
macho_mach_extract(struct image_params *imgp, const union macho_header *header,
        struct macho_fat_arch *arch, struct macho_mach_header *mach_part)
{
	struct vnode *vp = imgp->vp;
	struct thread *td = curthread;
	int error = 0;

	/* XXX FIXME Add support for both little/big endian */
	if (header->fat_header.magic == MACHO_FAT_MAGIC
	        || be32toh(header->fat_header.magic) == MACHO_FAT_MAGIC) {
		error = macho_fat_extract_arch(vp, &(header->fat_header), arch);
		if (error != 0) {
			printf("macho_fat_extract_arch error: %d\n", error);
			return error;
		}
	} else if (header->mach_header.magic == MACHO_MH_MAGIC) {
		arch->offset = 0;
	} else {
		printf("Bad Mach-O/Fat magic: 0x%lx, 0x%x\n",
		        (u_long) header->mach_header.magic, header->fat_header.magic);
		return ENOEXEC;
	}

	error = vn_rdwr(UIO_READ, vp, mach_part, sizeof(*mach_part), arch->offset,
	        UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
	if (error != 0 || mach_part->magic != MACHO_MH_MAGIC) {
		error = (error != 0) ? error : -1;
		printf(
		        "Mach-part error: %d, offset: 0x%lx, magic: 0x%lx, filetype: 0x%lx\n",
		        error, (u_long) arch->offset, (u_long) mach_part->magic,
		        (u_long) mach_part->filetype);
		return error;
	}

	if (header->mach_header.magic == MACHO_MH_MAGIC && arch->offset == 0) {
		arch->size = imgp->attr->va_size;
	}

	return 0;
}

static int
macho_map_create_page(vm_map_t map, vm_object_t object,
        vm_ooffset_t macho_start, vm_offset_t start, vm_offset_t end,
        vm_prot_t prot_min, vm_prot_t prot_max)
{
	int error = KERN_SUCCESS;

	/*
	 * Create the page if it doesn't exist yet. Ignore errors.
	 */
	vm_map_lock(map);
	error = vm_map_insert(map, NULL, 0, trunc_page(start), round_page(end),
	        prot_min, prot_max, 0);
	vm_map_unlock(map);

	/*
	 * Find the page from the underlying object.
	 */
	if (object) {
		struct sf_buf *sf;
		vm_offset_t off;

		sf = vm_imgact_map_page(object, macho_start);
		if (sf == NULL)
			return (KERN_FAILURE);
		off = macho_start - trunc_page(macho_start);
		error = copyout((caddr_t) sf_buf_kva(sf) + off, (caddr_t) start, end
		        - start);
		vm_imgact_unmap_page(sf);
		if (error) {
			return (KERN_FAILURE);
		}
	}

	return (KERN_SUCCESS);
}

static int
macho_map_align_insert(vm_map_t map, vm_object_t object,
        vm_ooffset_t macho_start, vm_offset_t start, vm_offset_t end,
        vm_prot_t prot_min, vm_prot_t prot_max)
{
	int rv;

	if (start != trunc_page(start)) {
		rv = macho_map_create_page(map, object, macho_start, start,
		        round_page(start), prot_min, prot_max);
		if (rv)
			return (rv);
		macho_start += round_page(start) - start;
		start = round_page(start);
	}
	if (end != round_page(end)) {
		rv = macho_map_create_page(map, object, macho_start + trunc_page(end)
		        - start, trunc_page(end), end, prot_min, prot_max);
		if (rv)
			return (rv);
		end = trunc_page(end);
	}
	if (end > start) {
		if (macho_start & PAGE_MASK) {
			/*
			 * The mapping is not page aligned. This means we have
			 * to copy the data. Sigh.
			 */
			vm_size_t sz = 0;
			rv = vm_map_find(map, NULL, 0, &start, end - start, 0,
			        VMFS_NO_SPACE, prot_min | VM_PROT_WRITE, prot_max, 0);
			if (rv)
				return (rv);
			if (object == NULL)
				return (KERN_SUCCESS);
			for (sz = 0; start < end; start += sz) {
				struct sf_buf *sf;
				vm_offset_t off;
				int error;

				sf = vm_imgact_map_page(object, macho_start);
				if (sf == NULL)
					return (KERN_FAILURE);
				off = macho_start - trunc_page(macho_start);
				sz = end - start;
				if (sz > PAGE_SIZE - off)
					sz = PAGE_SIZE - off;
				error = copyout((caddr_t) sf_buf_kva(sf) + off,
				        (caddr_t) start, sz);
				vm_imgact_unmap_page(sf);
				if (error) {
					return (KERN_FAILURE);
				}
				macho_start += sz;
			}
			rv = KERN_SUCCESS;
		} else {
			int cow = MAP_COPY_ON_WRITE | MAP_PREFAULT | (prot_min
			        & VM_PROT_WRITE ? 0 : MAP_DISABLE_COREDUMP);
			/* map is aligned only insert it to userspace map*/
			vm_object_reference(object);
			vm_map_lock(map);
			rv = vm_map_insert(map, object, macho_start, start, end, prot_min,
			        prot_max, cow);
			vm_map_unlock(map);
			if (rv != KERN_SUCCESS)
				vm_object_deallocate(object);
		}
		return (rv);
	}
	return (KERN_SUCCESS);
}

static int
macho_load_segment(struct image_params *imgp,
        struct macho_segment_command *scp, uint32_t type, off_t macho_start,
        off_t macho_size)
{
	/*XXX XXX XXX memsz = scp->vmsize, filesz = scp->filesize */
	size_t map_len;
	vm_map_t map;
	vm_object_t object;
	vm_offset_t map_addr;
	off_t file_offset;
	size_t copy_len;
	int error;

	object = imgp->object;
	map = &imgp->proc->p_vmspace->vm_map;

	file_offset = macho_start + scp->fileoff;

	map_addr = trunc_page(scp->vmaddr);
	map_len = round_page(scp->filesize);

	printf("cmd 0x%lx\n", (u_long) scp->cmd);
	printf("cmdsize %ld\n", (u_long) scp->cmdsize);
	printf("segname %s\n", scp->segname);
	printf("vmaddr 0x%lx\n", (u_long) scp->vmaddr);
	printf("vmsize %ld\n", (u_long) scp->vmsize);
	printf("fileoff 0x%lx\n", (u_long) scp->fileoff);
	printf("filesize %ld\n", (u_long) scp->filesize);
	printf("maxprot 0x%x\n", scp->maxprot);
	printf("initprot 0x%x\n", scp->initprot);
	printf("nsects %ld\n", (u_long) scp->nsects);
	printf("flags 0x%lx\n", (u_long) scp->flags);
	printf("macho-size: %ld\n", (u_long) macho_size);
	printf("==================================\n");

	if ((int32_t) scp->filesize < 0 || scp->filesize + macho_start
	        > imgp->attr->va_size || scp->fileoff + scp->filesize > macho_size) {
		printf("Bad (seg/file/macho)size: %ld %ld %ld %ld\n",
		        (u_long) scp->filesize, (u_long) scp->fileoff,
		        (u_long) macho_size, (u_long) imgp->attr->va_size);
		return ENOEXEC;
	}

	/*
	 * Ensure that the number of sections specified would fit
	 * within the load command size.
	 */
	if ((scp->cmdsize - sizeof(struct macho_load_command))
	        / sizeof(struct macho_section) < scp->nsects) {
		printf("Bad cmdsize/nsect: %lu %lu %lu %lu %ld\n",
		        (u_long) scp->cmdsize, (u_long) ((scp->cmdsize
		                - sizeof(struct macho_load_command))
		                / sizeof(struct macho_section)),
		        (u_long) sizeof(struct macho_load_command),
		        (u_long) sizeof(struct macho_section), (u_long) scp->nsects);
		return ENOEXEC;
	}

	if (strcmp(scp->segname, "__PAGEZERO") == 0)
		return 0;

	if (strcmp(scp->segname, "__TEXT") != 0 &&
		strcmp(scp->segname, "__DATA") != 0 &&
		strcmp(scp->segname, "__LOCK") != 0 &&
		strcmp(scp->segname, "__OBJC") != 0 &&
		strcmp(scp->segname, "__CGSERVER") != 0 &&
		strcmp(scp->segname, "__IMAGE") != 0 &&
		strcmp(scp->segname, "__LINKEDIT") != 0) {
		printf("Unknown segname: %s\n", scp->segname);
		return ENOEXEC;
	}

	if (type == MACHO_MH_EXECUTE) {
		if (strcmp(scp->segname, "__TEXT") == 0) {

			PROC_LOCK(imgp->proc);
			struct vmspace *vmspace = imgp->proc->p_vmspace;
			vmspace->vm_tsize = round_page(scp->vmsize);
			vmspace->vm_taddr = (caddr_t) (uintptr_t) map_addr;
			PROC_UNLOCK(imgp->proc);
		}

		if ((strcmp(scp->segname, "__DATA") == 0) ||
			(strcmp(scp->segname, "__OBJC") == 0) ||
			(strcmp(scp->segname, "__IMAGE") == 0) ||
			(strcmp(scp->segname, "__CGSERVER") == 0)) {

			PROC_LOCK(imgp->proc);
			struct vmspace *vmspace = imgp->proc->p_vmspace;
			vmspace->vm_dsize = round_page(scp->vmsize);
			vmspace->vm_daddr = (caddr_t) (uintptr_t) map_addr;
			PROC_UNLOCK(imgp->proc);
		}
	}

	/*
	 * Some libraries do not have a load base address. just skip them.
	 */
	if (map_addr == 0)
		return ENOMEM;

	if (scp->filesize > 0) {
		error = macho_map_align_insert(map, object, file_offset, map_addr,
		        map_addr + map_len, scp->initprot, scp->maxprot);
		if (error != KERN_SUCCESS)
			return EINVAL;

		/* we can stop now if we've covered it all */
		if (scp->filesize == macho_size) {
			return 0;
		}
	}

	copy_len = scp->vmsize - map_len;

	if (copy_len > 0) {
		struct sf_buf *sf;
		vm_offset_t off;

		map_addr += map_len;
		map_len = round_page(copy_len);
		error = macho_map_align_insert(map, object, file_offset, map_addr,
		        map_addr + map_len, scp->initprot, scp->maxprot);
		if (error != KERN_SUCCESS)
			return EINVAL;

		sf = vm_imgact_map_page(object, file_offset /*+scp->filesize*/);
		if (sf == NULL)
			return EIO;

		/* send the page fragment to user space */
		off = trunc_page_ps(file_offset /*+scp->filesize*/, PAGE_SIZE)
		        - trunc_page(file_offset /*+scp->filesize*/);
		error = copyout((caddr_t) sf_buf_kva(sf) + off, (caddr_t) map_addr,
		        copy_len);
		vm_imgact_unmap_page(sf);
		if (error) {
			printf("Error %d happend.\n", error);
			printf(
			        "0x%lx, %ld, %ld, 0x%lx, 0x%lx, %ld, 0x%lx, %ld, 0x%lx, %ld\n",
			        (u_long) map_addr, (u_long) map_len, (u_long) copy_len,
			        (u_long) off, (u_long) file_offset, (u_long) macho_size,
			        (u_long) scp->fileoff, (u_long) scp->filesize,
			        (u_long) scp->vmaddr, (u_long) scp->vmsize);
			return error;
		}

	}

	printf("Calling vm_map_protect ...\n");
	/*
	 * set it to the specified protection.
	 * XXX had better undo the damage from pasting over the cracks here!
	 */
	vm_map_protect(map, trunc_page(map_addr), round_page(map_addr + map_len),
	        scp->initprot, FALSE);

	return 0;
}


static int
macho_loadfile(struct proc *p, const char *path, u_long *res_entry, int depth)
{
	struct {
		struct nameidata nd;
		struct vattr attr;
		struct image_params image_params;
	}*tempdata;
	const union macho_header *hdr = NULL;
	struct macho_fat_arch arch;
	struct macho_mach_header mach_part;
	struct nameidata *nd;
	struct vattr *attr;
	struct image_params *imgp;
	int error = 0;

	tempdata = malloc(sizeof(*tempdata), M_TEMP, M_WAITOK);
	nd = &tempdata->nd;
	attr = &tempdata->attr;
	imgp = &tempdata->image_params;

	/*
	 * Initialize part of the common data
	 */
	imgp->proc = p;
	imgp->attr = attr;
	imgp->firstpage = NULL;
	imgp->image_header = NULL;
	imgp->object = NULL;
	imgp->execlabel = NULL;

	NDINIT(nd, LOOKUP, LOCKLEAF | FOLLOW, UIO_SYSSPACE, path, curthread);
	if ((error = namei(nd)) != 0) {
		nd->ni_vp = NULL;
		goto fail;
	}
	NDFREE(nd, NDF_ONLY_PNBUF);
	imgp->vp = nd->ni_vp;

	/*
	 * Check permissions, modes, uid, etc on the file, and "open" it.
	 */
	error = exec_check_permissions(imgp);
	if (error)
		goto fail;

	error = exec_map_first_page(imgp);
	if (error)
		goto fail;

	/*
	 * Also make certain that the interpreter stays the same, so set
	 * its VV_TEXT flag, too.
	 */
	VOP_SET_TEXT(nd->ni_vp);

	imgp->object = nd->ni_vp->v_object;

	hdr = (const union macho_header *) imgp->image_header;

	/*
	 * Here we should find/load segments and sections from our new file (that is lib).
	 * Before that, we need to determine arch and (if it's Fat) its apropriate Mach part.
	 */
	error = macho_mach_extract(imgp, hdr, &arch, &mach_part);
	if (error != 0) {
		goto fail;
	}

	/*mach_part > file_size*/
	if (arch.size > imgp->attr->va_size) {
		error = ENOEXEC;
		goto fail;
	}

	error = macho_parse_machfile(imgp, &mach_part, arch.offset, arch.size,
	        depth, res_entry);

	fail: if (imgp->firstpage)
		exec_unmap_first_page(imgp);

	if (nd->ni_vp)
		vput(nd->ni_vp);

	free(tempdata, M_TEMP);

	return (error);
}


static int
macho_load_dyn(struct proc *p, struct macho_load_command *dlcp, int type,
        u_long *res_ent, int depth)
{
	char *name = (char *) dlcp;
	char *np = NULL;
	char path[MAXPATHLEN] = "";

	int error = ENOEXEC;

	if (type == MACHO_MH_DYLINKER) {
		name += ((struct macho_dylinker_command *) dlcp)->name.offset;
	} else if (type == MACHO_MH_DYLIB) {
		name += ((struct macho_dylib_command *) dlcp)->dylib.name.offset;
	} else {
		return ENOEXEC;
	}

	/*
	 *	Check for a proper null terminated string.
	 */
	np = name;
	do {
		if (np >= (char *) dlcp + dlcp->cmdsize)
			return ENOEXEC;
	} while (*np++);

	snprintf(path, MAXPATHLEN, "%s%s", "/", name);
	printf("loading %s at %s\n", (type == MACHO_MH_DYLINKER) ? "linker"
	        : "library", path);
	/* load/parse/map new dyn(linker/lib) */
	error = macho_loadfile(p, path, res_ent, depth);

	return error;

}

static int
macho_parse_machfile(struct image_params *imgp,
        struct macho_mach_header *header, off_t file_offset, off_t macho_size,
        int depth, u_long *res_ent)
{
	struct macho_load_command lc;
	struct macho_load_command *lcp = &lc;
	struct vnode *vp = imgp->vp;
	struct thread *td = curthread;
	int error = 0;

	if (header->filetype == MACHO_MH_EXECUTE && depth != 0) {
		/* we are executing IFF we're in depth 0 */
		printf("Depth isn't 0 for Mach-O Executables!: %d\n", depth);
		return -1;
	} else if ((header->filetype == MACHO_MH_DYLINKER || header->filetype
	        == MACHO_MH_DYLIB) && (depth != 2 && depth != 1)) {
		/* we're loading dependency libs IFF we're in depth 1 or 2 */
		printf("Depth isn't 2 for Mach-O Dyn(*)s!: %d\n", depth);
		return -1;
	} else if (depth > 2) {
		/* WT**** !!! */
		return E2BIG;
	}

	if (header->filetype != MACHO_MH_PRELOAD &&
		header->filetype != MACHO_MH_EXECUTE &&
		header->filetype != MACHO_MH_DYLINKER &&
		header->filetype != MACHO_MH_DYLIB &&
		header->filetype != MACHO_MH_BUNDLE) {
		printf("Unsupported Mach-O filetype 0x%lx\n", (u_long) header->filetype);
		return ENOEXEC;
	}

	if ((off_t) (sizeof(struct macho_mach_header) + header->sizeofcmds)
	        > macho_size) {
		printf("Too big cmd size. sizeofcmds:%ld, machosize:%ld, sizeof:%lu\n",
				(u_long) header->sizeofcmds, (u_long) macho_size,
		        (u_long) sizeof(struct macho_mach_header));
		return ENOEXEC;
	}

	printf("magic 0x%lx\n", (u_long) header->magic);
	printf("cputype %x\n", header->cputype);
	printf("cpusubtype %d\n", header->cpusubtype);
	printf("filetype 0x%lx\n", (u_long) header->filetype);
	printf("ncmds %ld\n", (u_long) header->ncmds);
	printf("sizeofcmds %ld\n", (u_long) header->sizeofcmds);
	printf("flags 0x%lx\n", (u_long) header->flags);
	printf("macho-size: %ld\n", (u_long) macho_size);
	printf("==================================\n");

	off_t off = file_offset + sizeof(struct macho_mach_header);
	size_t old_cmd_sz = sizeof(lc);
	int i = 0;
	for (i = 0; i < header->ncmds; i++) {

		error = vn_rdwr(UIO_READ, vp, &lc, sizeof(lc), off, UIO_SYSSPACE,
		        IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
		if (error != 0)
			goto bad;

		if (old_cmd_sz < lc.cmdsize) {
			if (lc.cmdsize > 4096) {
				printf("Bad command size %lu\n", (u_long) lc.cmdsize);
				goto bad;
			}

			if (lcp != &lc) {
				free(lcp, M_TEMP);
			}
			lcp = malloc(lc.cmdsize, M_TEMP, M_WAITOK);
			old_cmd_sz = lc.cmdsize;
		}

		error = vn_rdwr(UIO_READ, vp, lcp, lc.cmdsize, off, UIO_SYSSPACE,
		        IO_NODELOCKED, td->td_ucred, NOCRED, NULL, td);
		if (error != 0)
			goto bad;

		off += lcp->cmdsize;

		printf("Current CMD: 0x%lx SIZE: 0x%lx [0x%lx]\n", (u_long) lcp->cmd,
		        (u_long) lcp->cmdsize, (u_long) lc.cmdsize);

		switch (lcp->cmd) {
		case MACHO_LC_SEGMENT:
			error = macho_load_segment(imgp,
			        (struct macho_segment_command *) lcp, header->filetype,
			        file_offset, macho_size); /* XXX XXX check file_offset is correct offset */
			if (error == ENOMEM) {
				printf("load segment failed, skipping\n");
				i = header->ncmds;
				error = 0;
				continue;
			} else if (error != 0) {
				printf("load segment failed, aborting\n");
				goto bad;
			}
			printf("Segment %s loaded successfully!\n",
			        ((struct macho_segment_command *) lcp)->segname);
			break;
		case MACHO_LC_LOAD_DYLINKER:
			error = macho_load_dyn(imgp->proc, lcp, MACHO_MH_DYLINKER, res_ent,
			        depth + 1);
			if (error != 0) {
				printf("load linker failed\n");
				goto bad;
			}
			/* XXX FIXME mark dynamic == yes. if i should do extra thing that what is done. */
			break;
		case MACHO_LC_LOAD_DYLIB:
			/*
			 * We should only load libraries that are required by this binary,
			 * Not libraries required by those libraries themselves.
			 */
			if (depth >= 1)
				break;
			error = macho_load_dyn(imgp->proc, lcp, MACHO_MH_DYLIB, res_ent,
			        depth + 1);
			if (error != 0) {
				printf("load dylib failed\n");
				goto bad;
			}
			break;

		case MACHO_LC_THREAD:
		case MACHO_LC_UNIXTHREAD:
			if (header->filetype == MACHO_MH_DYLINKER || *((caddr_t) (res_ent))
			        == 0) {
				*res_ent = macho_thread_entry(
				        (struct macho_thread_command *) lcp);
			} else {
				macho_thread_entry((struct macho_thread_command *) lcp);
			}
			break;

		case MACHO_LC_ID_DYLINKER:
		case MACHO_LC_ID_DYLIB:
		case MACHO_LC_SYMTAB:
		case MACHO_LC_DYSYMTAB:
			break;
		default:
			printf("Unhandled Mach-O command 0x%lx\n", (u_long) lcp->cmd);
			break;
		}
	}
	error = 0;

	bad:

	if (lcp != &lc) {
		free(lcp, M_TEMP);
	}
	return error;

}

static int
exec_macho_imgact(struct image_params *imgp)
{
	union macho_header *header = (union macho_header *) imgp->image_header;
	struct macho_fat_arch arch;
	struct macho_mach_header mach_part;
	u_long entry_addr;
	struct sysentvec *sv = &macho_freebsd_sysvec;
	int error = 0;

	error = macho_mach_extract(imgp, header, &arch, &mach_part);
	if (error != 0) {
		printf("macho_mach_extract error: %d\n", error);
		return ENOEXEC;
	}

	/*
	 * Now we have all thing we need to parse.
	 * A part of memory (mach_part) that we know :
	 * 	1) it's compatible with our cpu.
	 * 	2) it's what we should run.
	 * whether it's whole mach-o file or compatible part of fat mach-o file
	 */

	/*mach_part > file_size*/
	if (arch.size > imgp->attr->va_size) {
		return ENOEXEC;
	}

	/* XXX XXX is it correct to do this here ? */
	VOP_UNLOCK(imgp->vp, 0);

	error = exec_new_vmspace(imgp, sv);
	imgp->proc->p_sysent = sv;

	vn_lock(imgp->vp, LK_EXCLUSIVE | LK_RETRY);
	if (error != 0) {
		printf("exec_new_vmspace error: %d\n", error);
	}
	/* END of doubt region */

	error = macho_parse_machfile(imgp, &mach_part, arch.offset, arch.size, 0,
	        &entry_addr);
	if (error != 0) {
		printf("macho_parse_machfile error: %d\n", error);
	}

	imgp->entry_addr = entry_addr;

	return error;
}


/*
 * Tell kern_execve.c about it, with a little help from the linker.
 */
static struct execsw macho_execsw = { exec_macho_imgact, "macho" };
EXEC_SET(macho, macho_execsw);

