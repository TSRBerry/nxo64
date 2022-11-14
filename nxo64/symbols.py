class ElfSym(object):
    resolved = None

    def __init__(self, name, info, other, shndx, value, size):
        """
            :type name: str
            :type info: int
            :type other: int
            :type shndx: int
            :type value: int
            :type size: int
        """
        self.name = name
        self.shndx = shndx
        self.value = value
        self.size = size

        self.vis = other & 3
        self.type = info & 0xF
        self.bind = info >> 4

    def __repr__(self):
        return 'Sym(name=%r, shndx=0x%X, value=0x%X, size=0x%X, vis=%r, type=%r, bind=%r)' % (
            self.name, self.shndx, self.value, self.size, self.vis, self.type, self.bind)
