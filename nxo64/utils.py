import struct

from .compat import bytes_to_list, iter_range, list_to_bytes


def kip1_blz_decompress(compressed):
    """
        :type compressed: bytearray
    """
    compressed_size, init_index, uncompressed_addl_size = struct.unpack('<III', compressed[-0xC:])
    decompressed = compressed[:] + b'\x00' * uncompressed_addl_size
    decompressed_size = len(decompressed)
    if not (compressed_size + uncompressed_addl_size):
        return b''
    decompressed = bytes_to_list(decompressed)
    cmp_start = len(compressed) - compressed_size
    cmp_ofs = compressed_size - init_index
    out_ofs = compressed_size + uncompressed_addl_size
    while out_ofs > 0:
        cmp_ofs -= 1
        control = decompressed[cmp_start + cmp_ofs]
        for _ in iter_range(8):
            if control & 0x80:
                if cmp_ofs < 2 - cmp_start:
                    raise ValueError('Compression out of bounds!')
                cmp_ofs -= 2
                segmentoffset = compressed[cmp_start + cmp_ofs] | (compressed[cmp_start + cmp_ofs + 1] << 8)
                segmentsize = ((segmentoffset >> 12) & 0xF) + 3
                segmentoffset &= 0x0FFF
                segmentoffset += 2
                if out_ofs < segmentsize - cmp_start:
                    raise ValueError('Compression out of bounds!')
                for _ in iter_range(segmentsize):
                    if out_ofs + segmentoffset >= decompressed_size:
                        raise ValueError('Compression out of bounds!')
                    data = decompressed[cmp_start + out_ofs + segmentoffset]
                    out_ofs -= 1
                    decompressed[cmp_start + out_ofs] = data
            else:
                if out_ofs < 1 - cmp_start:
                    raise ValueError('Compression out of bounds!')
                out_ofs -= 1
                cmp_ofs -= 1
                decompressed[cmp_start + out_ofs] = decompressed[cmp_start + cmp_ofs]
            control <<= 1
            control &= 0xFF
            if not out_ofs:
                break
    return list_to_bytes(decompressed)


def suffixed_name(name, suffix):
    """
    :type name: str
    :type suffix: int
    :return: str
    """
    if suffix == 0:
        return name
    return '%s.%d' % (name, suffix)
