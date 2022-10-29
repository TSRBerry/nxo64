import struct


class BinFile(object):
    def __init__(self, li):
        """
            :type li: io.BytesIO
        """
        self._f = li

    def read(self, arg=None):
        """
            :type arg: Optional[Union[str, int]]
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

    def read_from(self, arg, offset):
        """
            :type arg: Optional[Union[str, int]]
            :type offset: int
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

    def close(self):
        self._f.close()

    def tell(self):
        return self._f.tell()
