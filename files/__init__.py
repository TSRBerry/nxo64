from .bin import BinFile
from .kip import KipFile
from .nro import NroFile
from .nso import NsoFile
from ..exceptions import NxoException


def load_nxo(fileobj):
    """
    :type fileobj: Union[io.BytesIO, io.BinaryIO]
    :return: Union[NsoFile, NroFile, KipFile]
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