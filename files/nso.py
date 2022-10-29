from __future__ import print_function

from lz4.block import decompress as uncompress

from .bin import BinFile
from .nxo_base import NxoFileBase
from ..exceptions import NxoException


class NsoFile(NxoFileBase):
    def __init__(self, fileobj):
        """
            :type fileobj: io.BytesIO
        """
        f = BinFile(fileobj)

        if f.read_from('4s', 0) != b'NSO0':
            raise NxoException('Invalid NSO magic')

        flags = f.read_from('I', 0xC)

        toff, tloc, tsize = f.read_from('III', 0x10)
        roff, rloc, rsize = f.read_from('III', 0x20)
        doff, dloc, dsize = f.read_from('III', 0x30)

        tfilesize, rfilesize, dfilesize = f.read_from('III', 0x60)
        bsssize = f.read_from('I', 0x3C)

        # print('load text: ')
        text = (uncompress(f.read_from(tfilesize, toff), uncompressed_size=tsize), None, tloc, tsize) if flags & 1 else (f.read_from(tfilesize, toff), toff, tloc, tsize)
        ro   = (uncompress(f.read_from(rfilesize, roff), uncompressed_size=rsize), None, rloc, rsize) if flags & 2 else (f.read_from(rfilesize, roff), roff, rloc, rsize)
        data = (uncompress(f.read_from(dfilesize, doff), uncompressed_size=dsize), None, dloc, dsize) if flags & 4 else (f.read_from(dfilesize, doff), doff, dloc, dsize)

        super(NsoFile, self).__init__(text, ro, data, bsssize)
