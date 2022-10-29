class Range(object):
    def __init__(self, start, size):
        """
            :type start: int
            :type size: int
        """
        self.start = start
        self.size = size
        self.end = start + size
        self._inclend = start + size - 1

    def overlaps(self, other):
        """
            :type other: Range
            :return: bool
        """
        return self.start <= other._inclend and other.start <= self._inclend

    def includes(self, other):
        """
            :type other: Range
            :return: bool
        """
        return other.start >= self.start and other._inclend <= self._inclend

    def __repr__(self):
        """
            :return: str
        """
        return 'Range(0x%X -> 0x%X)' % (self.start, self.end)
