from enum import IntEnum

from ..compat import iter_range


class DT(IntEnum):
    (NULL, NEEDED, PLTRELSZ, PLTGOT, HASH, STRTAB, SYMTAB, RELA, RELASZ,
     RELAENT, STRSZ, SYMENT, INIT, FINI, SONAME, RPATH, SYMBOLIC, REL,
     RELSZ, RELENT, PLTREL, DEBUG, TEXTREL, JMPREL, BIND_NOW, INIT_ARRAY,
     FINI_ARRAY, INIT_ARRAYSZ, FINI_ARRAYSZ, RUNPATH, FLAGS) = iter_range(31)

    GNU_HASH = 0x6ffffef5
    VERSYM = 0x6ffffff0
    RELACOUNT = 0x6ffffff9
    RELCOUNT = 0x6ffffffa
    FLAGS_1 = 0x6ffffffb
    VERDEF = 0x6ffffffc
    VERDEFNUM = 0x6ffffffd


MULTIPLE_DTS = {DT.NEEDED}
