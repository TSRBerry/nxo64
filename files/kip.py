from __future__ import print_function

from .bin import BinFile
from ..exceptions import NxoException
from .nxo_base import NxoFileBase
from ..utils import kip1_blz_decompress


class KipFile(NxoFileBase):
    def __init__(self, fileobj):
        """
            :type fileobj: io.BytesIO
        """
        f = BinFile(fileobj)

        if f.read_from('4s', 0) != b'KIP1':
            raise NxoException('Invalid KIP magic')

        flags = f.read_from('b', 0x1F)

        tloc, tsize, tfilesize = f.read_from('III', 0x20)
        rloc, rsize, rfilesize = f.read_from('III', 0x30)
        dloc, dsize, dfilesize = f.read_from('III', 0x40)

        toff = 0x100
        roff = toff + tfilesize
        doff = roff + rfilesize

        bsssize = f.read_from('I', 0x54)
        print('bss size 0x%x' % bsssize)

        print('load segments')
        text = (kip1_blz_decompress(f.read_from(tfilesize, toff)), None, tloc, tsize) if flags & 1 else (f.read_from(tfilesize, toff), toff, tloc, tsize)
        ro   = (kip1_blz_decompress(f.read_from(rfilesize, roff)), None, rloc, rsize) if flags & 2 else (f.read_from(rfilesize, roff), roff, rloc, rsize)
        data = (kip1_blz_decompress(f.read_from(dfilesize, doff)), None, dloc, dsize) if flags & 4 else (f.read_from(dfilesize, doff), doff, dloc, dsize)

        super(KipFile, self).__init__(text, ro, data, bsssize)
