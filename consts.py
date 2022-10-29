from enum import IntEnum

from .compat import iter_range


class STB(IntEnum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2


class STT(IntEnum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3


class R_AArch64(IntEnum):
    ABS64 = 257
    GLOB_DAT = 1025
    JUMP_SLOT = 1026
    RELATIVE = 1027
    TLSDESC = 1031


class R_Arm(IntEnum):
    ABS32 = 2
    TLS_DESC = 13
    GLOB_DAT = 21
    JUMP_SLOT = 22
    RELATIVE = 23


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



