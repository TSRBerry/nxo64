from . import Range, Section, Segment, SegmentKind
from ..utils import suffixed_name


class SegmentBuilder(object):
    segments = []  # type: list[Segment]

    def add_segment(self, start, size, name, kind):
        """
        :type start: int
        :type size: int
        :type name: str
        :type kind: SegmentKind
        """
        r = Range(start, size)
        for i in self.segments:
            assert not r.overlaps(i.range)
        self.segments.append(Segment(r, name, kind))

    def add_section(self, name, start, end=None, size=None):
        """
        :type name: str
        :type start: int
        :type end: int
        :type size: int
        """
        assert end is None or size is None
        if size == 0:
            return
        if size is None:
            size = end - start
        r = Range(start, size)
        for i in self.segments:
            if i.range.includes(r):
                i.add_section(Section(r, name))
                return
        assert False, "no containing segment for %r" % (name,)

    def flatten(self):
        self.segments.sort(key=lambda s: s.range.start)
        parts = []
        for segment in self.segments:
            suffix = 0
            segment.sections.sort(key=lambda s: s.range.start)
            pos = segment.range.start
            for section in segment.sections:
                if pos < section.range.start:
                    parts.append((pos, section.range.start, suffixed_name(segment.name, suffix), segment.kind))
                    suffix += 1
                    pos = section.range.start
                parts.append((section.range.start, section.range.end, section.name, segment.kind))
                pos = section.range.end
            if pos < segment.range.end:
                parts.append((pos, segment.range.end, suffixed_name(segment.name, suffix), segment.kind))
                suffix += 1
                pos = segment.range.end
        return parts
