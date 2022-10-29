from enum import IntEnum


class R_Arm(IntEnum):
    ABS32 = 2
    TLS_DESC = 13
    GLOB_DAT = 21
    JUMP_SLOT = 22
    RELATIVE = 23
    