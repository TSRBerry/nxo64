from .range import Range
from .section import Section


class Segment(object):
    sections = []  # type: list[Section]

    def __init__(self, r, name, kind):
        """
            :type r: Range
            :type name: str
            :type kind:
        """
        self.range = r
        self.name = name
        self.kind = kind

    def add_section(self, s):
        """
            :type s: Section
        """
        for i in self.sections:
            assert not i.range.overlaps(s.range), '%r overlaps %r' % (s, i)
        self.sections.append(s)
