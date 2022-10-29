# Copyright 2017 Reswitched Team
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or
# without fee is hereby granted, provided that the above copyright notice and this permission
# notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
# OR PERFORMANCE OF THIS SOFTWARE.

# nxo64.py: IDA loader (and library for reading nso/nro files)

from __future__ import print_function

from .compat import *
from .consts import *

from files import load_nxo

try:
    import idaapi
    import idc
except ImportError:
    pass
else:
    # IDA specific code
    def accept_file(li, n):
        print('accept_file')
        if not isinstance(n, int_types) or n == 0:
            li.seek(0)
            if li.read(4) == b'NSO0':
                return 'nxo.py: Switch binary (NSO)'
            li.seek(0)
            if li.read(4) == b'KIP1':
                return 'nxo.py: Switch binary (KIP)'
            li.seek(0x10)
            if li.read(4) == b'NRO0':
                return 'nxo.py: Switch binary (NRO)'
        return 0

    def ida_make_offset(f, ea):
        if f.armv7:
            idaapi.create_data(ea, idc.FF_DWORD, 4, idaapi.BADADDR)
        else:
            idaapi.create_data(ea, idc.FF_QWORD, 8, idaapi.BADADDR)
        idc.op_plain_offset(ea, 0, 0)

    def find_bl_targets(text_start, text_end):
        targets = set()
        for pc in range(text_start, text_end, 4):
            d = idc.get_wide_dword(pc)
            if (d & 0xfc000000) == 0x94000000:
                imm = d & 0x3ffffff
                if imm & 0x2000000:
                    imm |= ~0x1ffffff
                if 0 <= imm <= 2:
                    continue
                target = pc + imm * 4
                if text_start <= target < text_end:
                    targets.add(target)
        return targets

    def load_file(li, neflags, format):
        idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL | idaapi.SETPROC_LOADER)
        f = load_nxo(li)
        if f.armv7:
            idc.set_inf_attr(idc.INF_LFLAGS, idc.get_inf_attr(idc.INF_LFLAGS) | idc.LFLG_PC_FLAT)
        else:
            idc.set_inf_attr(idc.INF_LFLAGS, idc.get_inf_attr(idc.INF_LFLAGS) | idc.LFLG_64BIT)

        idc.set_inf_attr(idc.INF_DEMNAMES, idaapi.DEMNAM_GCC3)
        idaapi.set_compiler_id(idaapi.COMP_GNU)
        idaapi.add_til('gnulnx_arm' if f.armv7 else 'gnulnx_arm64', 1)

        loadbase = 0x60000000 if f.armv7 else 0x7100000000

        f.binfile.seek(0)
        as_string = f.binfile.read(f.bssoff)
        idaapi.mem2base(as_string, loadbase)
        if f.text[1] is not None:
            li.file2base(f.text[1], loadbase + f.text[2], loadbase + f.text[2] + f.text[3], True)
        if f.ro[1] is not None:
            li.file2base(f.ro[1], loadbase + f.ro[2], loadbase + f.ro[2] + f.ro[3], True)
        if f.data[1] is not None:
            li.file2base(f.data[1], loadbase + f.data[2], loadbase + f.data[2] + f.data[3], True)

        for start, end, name, kind in f.sections:
            if name.startswith('.got'):
                kind = 'CONST'
            idaapi.add_segm(0, loadbase+start, loadbase+end, name, kind)
            segm = idaapi.get_segm_by_name(name)
            if kind == 'CONST':
                segm.perm = idaapi.SEGPERM_READ
            elif kind == 'CODE':
                segm.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC
            elif kind == 'DATA':
                segm.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
            elif kind == 'BSS':
                segm.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
            idaapi.update_segm(segm)
            idaapi.set_segm_addressing(segm, 1 if f.armv7 else 2)

        # do imports
        # TODO: can we make imports show up in "Imports" window?
        undef_count = 0
        for s in f.symbols:
            if not s.shndx and s.name:
                undef_count += 1
        last_ea = max(loadbase + end for start, end, name, kind in f.sections)
        undef_entry_size = 8
        undef_ea = ((last_ea + 0xFFF) & ~0xFFF) + undef_entry_size  # plus 8 so we don't end up on the "end" symbol
        idaapi.add_segm(0, undef_ea, undef_ea+undef_count*undef_entry_size, "UNDEF", "XTRN")
        segm = idaapi.get_segm_by_name("UNDEF")
        segm.type = idaapi.SEG_XTRN
        idaapi.update_segm(segm)
        for i, s in enumerate(f.symbols):
            if not s.shndx and s.name:
                idaapi.create_data(undef_ea, idc.FF_QWORD, 8, idaapi.BADADDR)
                idaapi.force_name(undef_ea, s.name)
                s.resolved = undef_ea
                undef_ea += undef_entry_size
            elif i != 0:
                assert s.shndx
                s.resolved = loadbase + s.value
                if s.name:
                    if s.type == STT.FUNC:
                        print(hex(s.resolved), s.name)
                        idaapi.add_entry(s.resolved, s.resolved, s.name, 0)
                    else:
                        idaapi.force_name(s.resolved, s.name)

            else:
                # NULL symbol
                s.resolved = 0

        funcs = set()
        for s in f.symbols:
            if s.name and s.shndx and s.value:
                if s.type == STT.FUNC:
                    funcs.add(loadbase+s.value)

        got_name_lookup = {}
        for offset, r_type, sym, addend in f.relocations:
            target = offset + loadbase
            if r_type in (R_Arm.GLOB_DAT, R_Arm.JUMP_SLOT, R_Arm.ABS32):
                if not sym:
                    print('error: relocation at %X failed' % target)
                else:
                    idaapi.put_dword(target, sym.resolved)
            elif r_type == R_Arm.RELATIVE:
                idaapi.put_dword(target, idaapi.get_dword(target) + loadbase)
            elif r_type in (R_AArch64.GLOB_DAT, R_AArch64.JUMP_SLOT, R_AArch64.ABS64):
                idaapi.put_qword(target, sym.resolved + addend)
                if addend == 0:
                    got_name_lookup[offset] = sym.name
            elif r_type == R_AArch64.RELATIVE:
                idaapi.put_qword(target, loadbase + addend)
                if addend < f.textsize:
                    funcs.add(loadbase + addend)
            else:
                print('TODO r_type %d' % (r_type,))
            ida_make_offset(f, target)

        for func, target in f.plt_entries:
            if target in got_name_lookup:
                addr = loadbase + func
                funcs.add(addr)
                idaapi.force_name(addr, got_name_lookup[target])

        funcs |= find_bl_targets(loadbase, loadbase+f.textsize)

        for addr in sorted(funcs, reverse=True):
            idc.AutoMark(addr, idc.AU_CODE)
            idc.AutoMark(addr, idc.AU_PROC)

        return 1
