#ifndef _I386_MACHO_MACHDEP_H_
#define	_I386_MACHO_MACHDEP_H_

#define MACHO_I386_THREAD_STATE	-1
struct macho_i386_thread_state {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int edi;
	unsigned int esi;
	unsigned int ebp;
	unsigned int esp;
	unsigned int ss;
	unsigned int eflags;
	unsigned int eip;
	unsigned int cs;
	unsigned int ds;
	unsigned int es;
	unsigned int fs;
	unsigned int gs;
};

#define MACHO_I386_NEW_THREAD_STATE	1
struct macho_i386_saved_state {
	unsigned int gs;
	unsigned int fs;
	unsigned int es;
	unsigned int ds;
	unsigned int edi;
	unsigned int esi;
	unsigned int ebp;
	unsigned int esp;
	unsigned int ebx;
	unsigned int edx;
	unsigned int ecx;
	unsigned int eax;
	unsigned int trapno;
	unsigned int err;
	unsigned int eip;
	unsigned int cs;
	unsigned int efl;
	unsigned int uesp;
	unsigned int ss;
	struct vm86_segs {
		unsigned int es;
		unsigned int ds;
		unsigned int fs;
		unsigned int gs;
	} vm86_segs;
#define MACHO_I386_SAVED_ARGV_COUNT	7
	unsigned int argv_status;
	unsigned int argv[MACHO_I386_SAVED_ARGV_COUNT];
};

#endif /* !_I386_MACHO_MACHDEP_H_ */
