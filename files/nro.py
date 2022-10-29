from .bin import BinFile
from .nxo_base import NxoFileBase
from ..exceptions import NxoException


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
