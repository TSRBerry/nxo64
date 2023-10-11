try:
    # StrEnum is new in python 3.11
    from enum import StrEnum
except ImportError:
    try:
        from enum import Enum

        class StrEnum(str, Enum):
            pass
    except ImportError:
        from aenum import StrEnum


class SegmentKind(StrEnum):
    CODE = "CODE"
    CONST = "CONST"
    DATA = "DATA"
    BSS = "BSS"


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
        :rtype: bool
        """
        return self.start <= other._inclend and other.start <= self._inclend

    def includes(self, other):
        """
        :type other: Range
        :rtype: bool
        """
        return other.start >= self.start and other._inclend <= self._inclend

    def __repr__(self):
        """
        :rtype: str
        """
        return 'Range(0x%X -> 0x%X)' % (self.start, self.end)


class Section(object):
    def __init__(self, r, name):
        """
        :type r: Range
        :type name: str
        """
        self.range = r
        self.name = name

    def __repr__(self):
        """
        :rtype: str
        """
        return 'Section(%r, %r)' % (self.range, self.name)


class Segment(object):
    def __init__(self, r, name, kind):
        """
        :type r: Range
        :type name: str
        :type kind: SegmentKind
        """
        self.range = r
        self.name = name
        self.kind = kind
        self.sections = []  # type: list[Section]

    def add_section(self, s):
        """
        :type s: Section
        """
        for i in self.sections:
            assert not i.range.overlaps(s.range), '%r overlaps %r' % (s, i)
        self.sections.append(s)
