from __future__ import print_function

import re
import struct
from io import BytesIO

try:
    from enum import IntFlag
except ImportError:
    from aenum import IntFlag

from lz4.block import decompress as uncompress

from .memory import SegmentKind
from .memory.builder import SegmentBuilder
from .compat import iter_range, ascii_string
from .consts import MULTIPLE_DTS, DT, R_AArch64, R_Arm, R_FAKE_RELR
from .nxo_exceptions import NxoException
from .symbols import ElfSym
from .utils import kip1_blz_decompress


class NxoFlags(IntFlag):
    TEXT_COMPRESSED = 1
    RO_COMPRESSED = 2
    DATA_COMPRESSED = 4
    TEXT_HASH = 8
    RO_HASH = 16
    DATA_HASH = 32


def load_nxo(fileobj):
    """
    :type fileobj: io.BytesIO | io.BinaryIO
    :rtype: NsoFile | NroFile | KipFile
    """
    fileobj.seek(0)
    header = fileobj.read(0x14)

    if header[:4] == b'NSO0':
        return NsoFile(fileobj)
    elif header[0x10:0x14] == b'NRO0':
        return NroFile(fileobj)
    elif header[:4] == b'KIP1':
        return KipFile(fileobj)
    else:
        raise NxoException("not an NRO or NSO or KIP file")


def get_file_size(f):
    """
    :type f: io.BytesIO | BinFile
    :rtype: int
    """
    if isinstance(f, BinFile):
        return f.size()
    else:
        ptell = f.tell()
        f.seek(0, 2)
        filesize = f.tell()
        f.seek(ptell)
        return filesize


class BinFile(object):
    def __init__(self, li):
        """
        :type li: io.BytesIO
        """
        self._f = li

    def read(self, arg=None):
        """
        :type arg: str | int | None
        :rtype: bytes | tuple[Any, ...]
        """
        if isinstance(arg, str):
            fmt = '<' + arg
            size = struct.calcsize(fmt)
            raw = self._f.read(size)
            out = struct.unpack(fmt, raw)
            if len(out) == 1:
                return out[0]
            return out
        elif arg is None:
            return self._f.read()
        else:
            out = self._f.read(arg)
            return out

    def read_to_end(self):
        """
        :rtype: bytes | tuple[Any, ...]
        """
        return self.read(self.size() - self.tell())

    def size(self):
        """
        :rtype: int
        """
        return get_file_size(self._f)

    def read_from(self, arg, offset):
        """
        :param arg: str | int | None
        :param offset: int
        """
        old = self.tell()
        try:
            self.seek(offset)
            out = self.read(arg)
        finally:
            self.seek(old)
        return out

    def seek(self, off):
        """
        :type off: int
        """
        self._f.seek(off)

    def skip(self, dist):
        self.seek(self.tell() + dist)

    def close(self):
        self._f.close()

    def tell(self):
        """
        :rtype: int
        """
        return self._f.tell()


class NxoFileBase(object):
    # segment = (content, file offset, vaddr, vsize)
    def __init__(self, text, ro, data, bsssize):
        """
        :type text: tuple[bytes, int, int, int]
        :type ro: tuple[bytes, int, int, int]
        :type data: tuple[bytes, int, int, int]
        :type bsssize: int
        """
        self.text = text
        self.ro = ro
        self.data = data
        self.bsssize = bsssize
        self.textoff = text[2]
        self.textsize = text[3]
        self.rodataoff = ro[2]
        self.rodatasize = ro[3]
        self.dataoff = data[2]
        flatsize = data[2] + data[3]

        full = text[0]
        if ro[2] >= len(full):
            full += b'\x00' * (ro[2] - len(full))
        else:
            print('truncating .text?')
            full = full[:ro[2]]
        full += ro[0]
        if data[2] > len(full):
            full += b'\x00' * (data[2] - len(full))
        else:
            print('truncating .rodata?')
        full += data[0]
        f = BinFile(BytesIO(full))

        self.binfile = f

        # read MOD
        self.modoff = f.read_from('I', 4)

        f.seek(self.modoff)
        if f.read('4s') != b'MOD0':
            raise NxoException('invalid MOD0 magic')

        self.dynamicoff = self.modoff + f.read('i')
        self.bssoff = self.modoff + f.read('i')
        self.bssend = self.modoff + f.read('i')
        self.unwindoff = self.modoff + f.read('i')
        self.unwindend = self.modoff + f.read('i')
        self.moduleoff = self.modoff + f.read('i')

        self.datasize = self.bssoff - self.dataoff
        self.bsssize = self.bssend - self.bssoff

        self.isLibnx = False
        if f.read('4s') == b'LNY0':
            self.isLibnx = True
            self.libnx_got_start = self.modoff + f.read('i')
            self.libnx_got_end = self.modoff + f.read('i')

        self.segment_builder = builder = SegmentBuilder()
        for off, sz, name, kind in [
            (self.textoff, self.textsize, ".text", SegmentKind.CODE),
            (self.rodataoff, self.rodatasize, ".rodata", SegmentKind.CONST),
            (self.dataoff, self.datasize, ".data", SegmentKind.DATA),
            (self.bssoff, self.bsssize, ".bss", SegmentKind.BSS),
        ]:
            builder.add_segment(off, sz, name, kind)

        # read dynamic
        self.armv7 = (f.read_from('Q', self.dynamicoff) > 0xFFFFFFFF
                      or f.read_from('Q', self.dynamicoff + 0x10) > 0xFFFFFFFF)
        self.offsize = 4 if self.armv7 else 8

        f.seek(self.dynamicoff)
        self.dynamic = dynamic = {}
        for i in MULTIPLE_DTS:
            dynamic[i] = []
        for _ in iter_range((flatsize - self.dynamicoff) // 0x10):
            tag, val = f.read('II' if self.armv7 else 'QQ')
            if tag == DT.NULL:
                break
            if tag in MULTIPLE_DTS:
                dynamic[tag].append(val)
            else:
                dynamic[tag] = val
        self.dynamicsize = f.tell() - self.dynamicoff
        builder.add_section('.dynamic', self.dynamicoff, end=self.dynamicoff + self.dynamicsize)
        builder.add_section('.eh_frame_hdr', self.unwindoff, end=self.unwindend)

        # read .dynstr
        if DT.STRTAB in dynamic and DT.STRSZ in dynamic:
            f.seek(dynamic[DT.STRTAB])
            self.dynstr = f.read(dynamic[DT.STRSZ])
        else:
            self.dynstr = b'\x00'
            print('warning: no dynstr')

        for startkey, szkey, name in [
            (DT.STRTAB, DT.STRSZ, '.dynstr'),
            (DT.INIT_ARRAY, DT.INIT_ARRAYSZ, '.init_array'),
            (DT.FINI_ARRAY, DT.FINI_ARRAYSZ, '.fini_array'),
            (DT.RELA, DT.RELASZ, '.rela.dyn'),
            (DT.REL, DT.RELSZ, '.rel.dyn'),
            (DT.RELR, DT.RELRSZ, '.relr.dyn'),
            (DT.JMPREL, DT.PLTRELSZ, ('.rel.plt' if self.armv7 else '.rela.plt')),
        ]:
            if startkey in dynamic and szkey in dynamic:
                builder.add_section(name, dynamic[startkey], size=dynamic[szkey])

        # TODO
        # build_id = content.find('\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00')
        # if build_id >= 0:
        #    builder.add_section('.note.gnu.build-id', build_id, size=0x24)
        # else:
        #    build_id = content.index('\x04\x00\x00\x00\x10\x00\x00\x00\x03\x00\x00\x00GNU\x00')
        #    if build_id >= 0:
        #        builder.add_section('.note.gnu.build-id', build_id, size=0x20)

        if DT.HASH in dynamic:
            hash_start = dynamic[DT.HASH]
            f.seek(hash_start)
            nbucket, nchain = f.read('II')
            f.skip(nbucket * 4)
            f.skip(nchain * 4)
            hash_end = f.tell()
            builder.add_section('.hash', hash_start, end=hash_end)

        if DT.GNU_HASH in dynamic:
            gnuhash_start = dynamic[DT.GNU_HASH]
            f.seek(gnuhash_start)
            nbuckets, symoffset, bloom_size, bloom_shift = f.read('IIII')
            f.skip(bloom_size * self.offsize)
            buckets = [f.read('I') for _ in range(nbuckets)]

            max_symix = max(buckets) if buckets else 0
            if max_symix >= symoffset:
                f.skip((max_symix - symoffset) * 4)
                while (f.read('I') & 1) == 0:
                    pass
            gnuhash_end = f.tell()
            builder.add_section('.gnu.hash', gnuhash_start, end=gnuhash_end)

        self.needed = [self.get_dynstr(i) for i in self.dynamic[DT.NEEDED]]

        # load .dynsym
        self.symbols = symbols = []
        if DT.SYMTAB in dynamic and DT.STRTAB in dynamic:
            f.seek(dynamic[DT.SYMTAB])
            while True:
                if dynamic[DT.SYMTAB] < dynamic[DT.STRTAB] <= f.tell():
                    break
                if self.armv7:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = f.read('IIIBBH')
                else:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = f.read('IBBHQQ')
                if st_name > len(self.dynstr):
                    break
                symbols.append(ElfSym(self.get_dynstr(st_name), st_info, st_other, st_shndx, st_value, st_size))
            builder.add_section('.dynsym', dynamic[DT.SYMTAB], end=f.tell())

        self.plt_entries = []
        self.relocations = []
        locations = set()
        plt_got_end = None
        if DT.REL in dynamic and DT.RELSZ in dynamic:
            locations |= self.process_relocations(f, symbols, dynamic[DT.REL], dynamic[DT.RELSZ])

        if DT.RELA in dynamic and DT.RELASZ in dynamic:
            locations |= self.process_relocations(f, symbols, dynamic[DT.RELA], dynamic[DT.RELASZ])

        if DT.RELR in dynamic:
            locations |= self.process_relocations_relr(f, dynamic[DT.RELR], dynamic[DT.RELRSZ])

        if DT.JMPREL in dynamic and DT.PLTRELSZ in dynamic:
            pltlocations = self.process_relocations(f, symbols, dynamic[DT.JMPREL], dynamic[DT.PLTRELSZ])
            locations |= pltlocations

            plt_got_start = min(pltlocations)
            plt_got_end = max(pltlocations) + self.offsize
            if DT.PLTGOT in dynamic:
                builder.add_section('.got.plt', dynamic[DT.PLTGOT], end=plt_got_end)

            if not self.armv7:
                f.seek(0)
                text = f.read(self.textsize)
                last = 12
                while True:
                    pos = text.find(struct.pack('<I', 0xD61F0220), last)
                    if pos == -1:
                        break
                    last = pos + 1
                    if (pos % 4) != 0:
                        continue
                    off = pos - 12
                    a, b, c, d = struct.unpack_from('<IIII', text, off)
                    if d == 0xD61F0220 and (a & 0x9f00001f) == 0x90000010 and (b & 0xffe003ff) == 0xf9400211:
                        base = off & ~0xFFF
                        immhi = (a >> 5) & 0x7ffff
                        immlo = (a >> 29) & 3
                        paddr = base + ((immlo << 12) | (immhi << 14))
                        poff = ((b >> 10) & 0xfff) << 3
                        target = paddr + poff
                        if plt_got_start <= target < plt_got_end:
                            self.plt_entries.append((off, target))
                if len(self.plt_entries) > 0:
                    builder.add_section('.plt', min(self.plt_entries)[0], end=max(self.plt_entries)[0] + 0x10)

        if not self.isLibnx:
            # try to find the ".got" which should follow the ".got.plt"
            good = False
            got_start = (plt_got_end if plt_got_end is not None else self.dynamicoff + self.dynamicsize)
            got_end = self.offsize + got_start
            while (got_end in locations or (plt_got_end is None and got_end < dynamic[DT.INIT_ARRAY])) and (
                    DT.INIT_ARRAY not in dynamic or got_end < dynamic[DT.INIT_ARRAY]
                    or dynamic[DT.INIT_ARRAY] < got_start):
                good = True
                got_end += self.offsize

            if good:
                self.got_start = got_start
                self.got_end = got_end
                builder.add_section('.got', self.got_start, end=self.got_end)
        else:
            builder.add_section('.got', self.libnx_got_start, end=self.libnx_got_end)

        self.eh_table = []
        if not self.armv7:
            f.seek(self.unwindoff)
            version, eh_frame_ptr_enc, fde_count_enc, table_enc = f.read('BBBB')
            if not any(i == 0xff for i in (eh_frame_ptr_enc, fde_count_enc, table_enc)):  # DW_EH_PE_omit
                # assert eh_frame_ptr_enc == 0x1B # DW_EH_PE_pcrel | DW_EH_PE_sdata4
                # assert fde_count_enc == 0x03    # DW_EH_PE_absptr | DW_EH_PE_udata4
                # assert table_enc == 0x3B        # DW_EH_PE_datarel | DW_EH_PE_sdata4
                if eh_frame_ptr_enc == 0x1B and fde_count_enc == 0x03 and table_enc == 0x3B:
                    base_offset = f.tell()
                    eh_frame = base_offset + f.read('i')

                    fde_count = f.read('I')
                    # assert 8 * fde_count == self.unwindend - f.tell()
                    if 8 * fde_count <= self.unwindend - f.tell():
                        for i in range(fde_count):
                            pc = self.unwindoff + f.read('i')
                            entry = self.unwindoff + f.read('i')
                            self.eh_table.append((pc, entry))

                    # TODO: we miss the last one, but better than nothing
                    last_entry = sorted(self.eh_table, key=lambda x: x[1])[-1][1]
                    builder.add_section('.eh_frame', eh_frame, end=last_entry)

        self.sections = []
        for start, end, name, kind in builder.flatten():
            self.sections.append((start, end, name, kind))

    def process_relocations(self, f, symbols, offset, size):
        """
        :type f: BinFile
        :type symbols: list[ElfSym]
        :type offset: int
        :type size: int
        :rtype: set[int]
        """
        locations = set()
        f.seek(offset)
        relocsize = 8 if self.armv7 else 0x18
        for _ in iter_range(size // relocsize):
            # NOTE: currently assumes all armv7 relocs have no addends,
            # and all 64-bit ones do.
            if self.armv7:
                offset, info = f.read('II')
                addend = None
                r_type = info & 0xff
                r_sym = info >> 8
            else:
                offset, info, addend = f.read('QQq')
                r_type = info & 0xffffffff
                r_sym = info >> 32

            sym = symbols[r_sym] if r_sym != 0 else None

            if r_type != R_AArch64.TLSDESC and r_type != R_Arm.TLS_DESC:
                locations.add(offset)
            self.relocations.append((offset, r_type, sym, addend))
        return locations

    def process_relocations_relr(self, f, offset, size):
        locations = set()
        f.seek(offset)
        relocsize = 8
        for _ in iter_range(size // relocsize):
            entry = f.read('Q')
            if entry & 1:
                entry >>= 1
                i = 0
                while i < (relocsize * 8) - 1:
                    if entry & (1 << i):
                        locations.add(where + i * relocsize)
                        self.relocations.append((where + i * relocsize, R_FAKE_RELR, None, 0))
                    i += 1
                where += relocsize * ((relocsize * 8) - 1)
            else:
                # Where
                where = entry
                locations.add(where)
                self.relocations.append((where, R_FAKE_RELR, None, 0))
                where += relocsize
        return locations

    def get_dynstr(self, o):
        """
        :type o: int
        """
        return ascii_string(self.dynstr[o:self.dynstr.index(b'\x00', o)])

    def get_path_or_name(self):
        """
        :rtype: bytes | None
        """
        path = None
        for off, end, name, class_ in self.sections:
            if name == '.rodata' and 0x1000 > end - off > 8:
                id_ = self.binfile.read_from(end - off, off).lstrip(b'\x00')
                if len(id_) > 0:
                    length = struct.unpack_from('<I', id_, 0)[0]
                    if length + 4 <= len(id_):
                        id_ = id_[4:length + 4]
                        return id_

        self.binfile.seek(self.rodataoff)
        as_string = self.binfile.read(self.rodatasize)
        if path is None:
            strs = re.findall(r'[a-z]:[\\/][ -~]{5,}\.n[rs]s'.encode(), as_string, flags=re.IGNORECASE)
            if strs:
                return strs[-1]

        return None

    def get_name(self):
        """
        :rtype: bytes | None
        """
        name = self.get_path_or_name()
        if name is not None:
            name = name.split(b'/')[-1].split(b'\\')[-1]
            if name.lower().endswith((b'.nss', b'.nrs')):
                name = name[:-4]
        return name


class NsoFile(NxoFileBase):
    def __init__(self, fileobj):
        """
        :type fileobj: io.BytesIO
        """
        f = BinFile(fileobj)

        if f.read_from('4s', 0) != b'NSO0':
            raise NxoException('Invalid NSO magic')

        flags = NxoFlags(f.read_from('I', 0xC))

        toff, tloc, tsize = f.read_from('III', 0x10)
        roff, rloc, rsize = f.read_from('III', 0x20)
        doff, dloc, dsize = f.read_from('III', 0x30)

        tfilesize, rfilesize, dfilesize = f.read_from('III', 0x60)
        bsssize = f.read_from('I', 0x3C)

        # print('load text: ')
        text = ((uncompress(f.read_from(tfilesize, toff), uncompressed_size=tsize), None, tloc, tsize)
                if NxoFlags.TEXT_COMPRESSED in flags else (f.read_from(tfilesize, toff), toff, tloc, tsize))
        ro   = ((uncompress(f.read_from(rfilesize, roff), uncompressed_size=rsize), None, rloc, rsize)
                if NxoFlags.RO_COMPRESSED in flags else (f.read_from(rfilesize, roff), roff, rloc, rsize))
        data = ((uncompress(f.read_from(dfilesize, doff), uncompressed_size=dsize), None, dloc, dsize)
                if NxoFlags.DATA_COMPRESSED in flags else (f.read_from(dfilesize, doff), doff, dloc, dsize))

        super(NsoFile, self).__init__(text, ro, data, bsssize)


class NroFile(NxoFileBase):
    def __init__(self, fileobj):
        """
        :type fileobj: io.BytesIO
        """
        f = BinFile(fileobj)

        if f.read_from('4s', 0x10) != b'NRO0':
            raise NxoException('Invalid NRO magic')

        f.seek(0x20)

        tloc, tsize = f.read('II')
        rloc, rsize = f.read('II')
        dloc, dsize = f.read('II')
        bsssize = f.read_from('I', 0x28)

        text = (f.read_from(tsize, tloc), tloc, tloc, tsize)
        ro   = (f.read_from(rsize, rloc), rloc, rloc, rsize)
        data = (f.read_from(dsize, dloc), dloc, dloc, dsize)

        super(NroFile, self).__init__(text, ro, data, bsssize)


class KipFile(NxoFileBase):
    def __init__(self, fileobj):
        """
        :type fileobj: io.BytesIO
        """
        f = BinFile(fileobj)

        if f.read_from('4s', 0) != b'KIP1':
            raise NxoException('Invalid KIP magic')

        flags = NxoFlags(f.read_from('b', 0x1F))

        tloc, tsize, tfilesize = f.read_from('III', 0x20)
        rloc, rsize, rfilesize = f.read_from('III', 0x30)
        dloc, dsize, dfilesize = f.read_from('III', 0x40)

        toff = 0x100
        roff = toff + tfilesize
        doff = roff + rfilesize

        bsssize = f.read_from('I', 0x54)
        print('bss size 0x%x' % bsssize)

        print('load segments')
        text = ((kip1_blz_decompress(f.read_from(tfilesize, toff)), None, tloc, tsize)
                if NxoFlags.TEXT_COMPRESSED in flags else (f.read_from(tfilesize, toff), toff, tloc, tsize))
        ro   = ((kip1_blz_decompress(f.read_from(rfilesize, roff)), None, rloc, rsize)
                if NxoFlags.RO_COMPRESSED in flags else (f.read_from(rfilesize, roff), roff, rloc, rsize))
        data = ((kip1_blz_decompress(f.read_from(dfilesize, doff)), None, dloc, dsize)
                if NxoFlags.DATA_COMPRESSED in flags else (f.read_from(dfilesize, doff), doff, dloc, dsize))

        super(KipFile, self).__init__(text, ro, data, bsssize)
