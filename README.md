# FreeBSD_MachO

Implementation of Mach-O file format support for FreeBSD.

$EMUL_ROOT [EMUL_ROOT in exact writing] is shadow root i defined in imgact_macho.h.
	it defined as '/' now :D but i think some day it should be something like '/compat/darwin/'.
 
'test/out' is code.c compiled and linked in OSX system.
about 'test/dyld' and 'test/libSystem.B.dylib' read "simple test" below.

For a simple test:
	After loading module (or building kernel with it),
	Running 'test/out' should complain about not finding 'dyld' then copy it on $EMUL_ROOT/usr/bin.
	It should complain again because you should copy 'libSystem.B.dylib' to $EMUL_ROOT/usr/bin too.
	
	Now you should see by logs that segment mapped successfully.
	The rest is implementing syscall translation layer (for an OSX mach-o binary in FreeBSD land) that i'm doing it currently.